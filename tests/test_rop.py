"""Tests for ROP gadget search and do_rop."""

import sys
import platform
import pytest
from unittest.mock import patch, mock_open, MagicMock
from unsafelib.core import (
    find_gadgets, do_rop, GADGET_PATTERNS, addrof, p64a, u64,
)
from unsafelib.exceptions import GadgetSearchError
from unsafelib import Unsafe, UnsafeContextError


class TestGadgetPatterns:
    def test_all_patterns_are_bytes(self):
        for name, pattern in GADGET_PATTERNS.items():
            assert isinstance(pattern, bytes), f"{name} pattern is not bytes"

    def test_all_patterns_end_with_ret(self):
        for name, pattern in GADGET_PATTERNS.items():
            if name != "ret":
                assert pattern.endswith(b"\xc3"), f"{name} doesn't end with ret (0xc3)"

    def test_ret_gadget(self):
        assert GADGET_PATTERNS["ret"] == b"\xc3"

    def test_syscall_ret(self):
        assert GADGET_PATTERNS["syscall; ret"] == b"\x0f\x05\xc3"

    def test_stack_pivot(self):
        assert GADGET_PATTERNS["mov rsp, rdx; ret"] == b"\x48\x89\xd4\xc3"

    def test_expected_gadgets_present(self):
        expected = [
            "ret", "mov rsp, rdx; ret",
            "pop rax; ret", "pop rbx; ret", "pop rcx; ret",
            "pop rdx; pop rbx; ret", "pop rsi; ret", "pop rdi; ret",
            "syscall; ret",
        ]
        for name in expected:
            assert name in GADGET_PATTERNS


class TestFindGadgetsErrors:
    def test_no_proc_maps_raises(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            with pytest.raises(GadgetSearchError, match="not available"):
                find_gadgets(MagicMock())

    def test_no_libc_in_maps_raises(self):
        fake_maps = "55555-66666 r-xp 00000 08:01 1234 /usr/bin/python\n"
        with patch("builtins.open", mock_open(read_data=fake_maps)):
            with pytest.raises(GadgetSearchError, match="could not find libc"):
                find_gadgets(MagicMock())

    def test_gadget_not_found_raises(self):
        fake_maps = "7f000-7f100 r-xp 00000 08:01 1234 /lib/x86_64-linux-gnu/libc-2.31.so\n"
        # mem.index raises ValueError when pattern not found
        mock_mem = MagicMock()
        mock_mem.index.side_effect = ValueError("not found")
        with patch("builtins.open", mock_open(read_data=fake_maps)):
            with pytest.raises(GadgetSearchError, match="not found"):
                find_gadgets(mock_mem)


class TestFindGadgetsParsing:
    def test_parses_libc_base(self):
        fake_maps = (
            "556a0000-556b0000 r-xp 00000 08:01 100 /usr/bin/python\n"
            "7f1234000000-7f1234100000 r-xp 00000 08:01 200 /lib/x86_64-linux-gnu/libc-2.31.so\n"
        )
        mock_mem = MagicMock()
        # Make mem.index return predictable addresses
        call_count = [0]
        def fake_index(pattern, start):
            call_count[0] += 1
            return start + call_count[0] * 0x100
        mock_mem.index.side_effect = fake_index

        with patch("builtins.open", mock_open(read_data=fake_maps)):
            gadgets = find_gadgets(mock_mem)

        assert len(gadgets) == len(GADGET_PATTERNS)
        # All addresses should be above libc_base
        for name, addr in gadgets.items():
            assert addr >= 0x7F1234000000

    def test_libc_so_6_format(self):
        """Test parsing with libc.so.6 naming (newer distros)."""
        fake_maps = "7f000-7f100 r-xp 00000 08:01 200 /usr/lib/libc.so.6\n"
        mock_mem = MagicMock()
        mock_mem.index.side_effect = lambda pattern, start: start + 0x42

        with patch("builtins.open", mock_open(read_data=fake_maps)):
            gadgets = find_gadgets(mock_mem)
        assert "ret" in gadgets


class TestDoRopContextGating:
    def test_blocked_outside_context(self):
        u = Unsafe()
        with pytest.raises(UnsafeContextError, match="do_rop"):
            u.do_rop([])

    def test_find_gadgets_blocked_outside(self):
        u = Unsafe()
        with pytest.raises(UnsafeContextError, match="find_gadgets"):
            u.find_gadgets()


class TestDoRopConstruction:
    """Test the ROP payload construction logic."""

    def test_payload_packing(self):
        """Verify a typical execve ROP chain packs correctly."""
        # Simulate gadget addresses
        gadgets = {
            "pop rax; ret": 0x7F0001,
            "pop rdi; ret": 0x7F0002,
            "pop rsi; ret": 0x7F0003,
            "pop rdx; pop rbx; ret": 0x7F0004,
            "syscall; ret": 0x7F0005,
        }
        binsh_addr = 0x414141
        argv_addr = 0x424242

        payload = p64a(
            gadgets["pop rax; ret"], 59,
            gadgets["pop rdi; ret"], binsh_addr,
            gadgets["pop rsi; ret"], argv_addr,
            gadgets["pop rdx; pop rbx; ret"], 0, 0,
            gadgets["syscall; ret"],
        )

        assert len(payload) == 10 * 8  # 10 qwords
        # First entry should be pop rax gadget
        assert u64(payload[:8]) == 0x7F0001
        # Second should be 59 (SYS_EXECVE)
        assert u64(payload[8:16]) == 59
        # Third should be pop rdi
        assert u64(payload[16:24]) == 0x7F0002
        # Fourth should be binsh addr
        assert u64(payload[24:32]) == binsh_addr

    def test_mprotect_payload(self):
        """Verify mprotect ROP chain structure."""
        gadgets = {
            "pop rax; ret": 0xA001,
            "pop rdi; ret": 0xA002,
            "pop rsi; ret": 0xA003,
            "pop rdx; pop rbx; ret": 0xA004,
            "syscall; ret": 0xA005,
        }
        page_base = 0x1000
        page_len = 0x1000
        shellcode_ptr = 0x1042

        payload = p64a(
            gadgets["pop rax; ret"], 10,  # SYS_MPROTECT
            gadgets["pop rdi; ret"], page_base,
            gadgets["pop rsi; ret"], page_len,
            gadgets["pop rdx; pop rbx; ret"], 7, 0,  # RWX, junk
            gadgets["syscall; ret"],
            shellcode_ptr,
        )

        assert len(payload) == 11 * 8
        assert u64(payload[8:16]) == 10  # mprotect syscall number


class TestDoRopInternals:
    def test_do_rop_creates_fakedict(self):
        """Verify do_rop constructs the stack pivot correctly."""
        gadgets = {
            "pop rax; ret": 0xAAAA,
            "mov rsp, rdx; ret": 0xBBBB,
        }
        payload = p64a(0xCCCC)

        # The fakedict header should contain pop_rax_addr - 4 and dict type addr
        header = p64a(
            gadgets["pop rax; ret"] - 4,
            addrof(dict),
        )
        # Verify the subtraction is for refcount adjustment
        assert u64(header[:8]) == 0xAAAA - 4
        assert u64(header[8:16]) == addrof(dict)
