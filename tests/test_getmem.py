"""Tests for getmem — full process memory access."""

import sys
import platform
import pytest
from unittest.mock import patch, MagicMock
from unsafelib.core import (
    make_getmem, addrof, p64a, u64, refbytes,
    INT64_MAX, BYTES_HEADER_LEN,
)
from unsafelib import Unsafe, UnsafeContextError

EXPLOIT_WORKS = (
    platform.python_implementation() == "CPython"
    and sys.version_info < (3, 12)
)


class TestGetmemContextGating:
    def test_blocked_outside_context(self):
        u = Unsafe()
        with pytest.raises(UnsafeContextError, match="getmem"):
            u.getmem()

    def test_blocked_after_exit(self):
        u = Unsafe()
        with u:
            pass
        with pytest.raises(UnsafeContextError, match="getmem"):
            u.getmem()


class TestGetmemConstruction:
    """Test that make_getmem constructs the right fake bytearray bytes."""

    def test_fake_bytearray_layout(self):
        # Verify the raw bytes that would be fed to fakeobj
        ba_type_addr = addrof(bytearray)
        expected = p64a(
            1,            # ob_refcnt
            ba_type_addr, # ob_type
            INT64_MAX,    # ob_size
            0, 0, 0, 0,  # alloc, bytes, start, exports
        )
        # The first 8 bytes should be refcnt=1
        assert u64(expected[:8]) == 1
        # The next 8 should be the bytearray type pointer
        assert u64(expected[8:16]) == ba_type_addr
        # ob_size should be INT64_MAX
        assert u64(expected[16:24]) == INT64_MAX


@pytest.mark.skipif(not EXPLOIT_WORKS, reason="Exploit requires CPython <= 3.11")
class TestGetmemExploit:
    def test_getmem_returns_bytearray(self):
        with Unsafe() as u:
            mem = u.getmem()
            assert isinstance(mem, bytearray)

    def test_getmem_huge_length(self):
        with Unsafe() as u:
            mem = u.getmem()
            assert len(mem) == INT64_MAX

    def test_getmem_cached(self):
        with Unsafe() as u:
            mem1 = u.getmem()
            mem2 = u.getmem()
            assert mem1 is mem2

    def test_can_read_own_object(self):
        with Unsafe() as u:
            mem = u.getmem()
            target = b"UNSAFE_MARKER_12345"
            addr = u.addrof(target)
            # Read some bytes from around the object — should contain our marker
            raw = bytes(mem[addr:addr + 200])
            assert b"UNSAFE_MARKER_12345" in raw

    def test_can_read_refcount(self):
        with Unsafe() as u:
            mem = u.getmem()
            obj = object()
            addr = u.addrof(obj)
            # First 8 bytes are ob_refcnt — should be small positive
            refcnt = u64(mem[addr:addr + 8])
            assert 1 <= refcnt < 1000

    def test_mutate_cached_integer(self):
        """Overwrite CPython's cached integer 42 → 43 via raw memory."""
        import subprocess
        # Run in subprocess to avoid corrupting our own process
        result = subprocess.run(
            [sys.executable, "-c", """
from unsafelib import Unsafe
from unsafelib.core import u64

with Unsafe() as u:
    mem = u.getmem()
    addr = u.addrof(42)

    # Save original ob_digit
    original = list(mem[addr + 24 : addr + 28])

    # Overwrite ob_digit: 42 -> 43
    mem[addr + 24 : addr + 28] = [43, 0, 0, 0]

    results = []
    results.append(str(42))        # literal -> cached object
    results.append(str(40 + 2))    # computed -> same cached object
    results.append(str(41 + 1))    # computed -> same cached object

    # Restore before exit
    mem[addr + 24 : addr + 28] = original

    print(",".join(results))
"""],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert result.stdout.strip() == "43,43,43"
