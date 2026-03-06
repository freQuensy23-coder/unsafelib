"""Tests for fakeobj primitive — the core exploit."""

import sys
import platform
import pytest
from unittest.mock import patch, MagicMock
from unsafelib.core import (
    fakeobj_once, FakeobjPrimitive, addrof, p64a, refbytes,
    BYTES_HEADER_LEN, TUPLE_HEADER_LEN,
)
from unsafelib import Unsafe, UnsafeContextError

# The actual exploit only works on CPython <= 3.11
EXPLOIT_WORKS = (
    platform.python_implementation() == "CPython"
    and sys.version_info < (3, 12)
)


class TestFakeobjPrimitiveInit:
    def test_creates_with_nogc(self):
        nogc = []
        fp = FakeobjPrimitive(nogc)
        assert fp._reusable_bytearray is None
        assert fp._reusable_tuple == (None,)

    def test_nogc_reference_kept(self):
        nogc = []
        fp = FakeobjPrimitive(nogc)
        assert fp._nogc is nogc


class TestFakeobjContextGating:
    def test_fakeobj_blocked_outside_context(self):
        u = Unsafe()
        with pytest.raises(UnsafeContextError, match="fakeobj"):
            u.fakeobj(0x41414141)

    def test_fakeobj_blocked_after_context_exit(self):
        u = Unsafe()
        with u:
            pass
        with pytest.raises(UnsafeContextError, match="fakeobj"):
            u.fakeobj(0x41414141)


@pytest.mark.skipif(not EXPLOIT_WORKS, reason="Exploit requires CPython <= 3.11")
class TestFakeobjExploit:
    def test_fakeobj_once_returns_object(self):
        # Forge a reference to an existing object (an int)
        target = 12345678
        nogc = []
        result = fakeobj_once(addrof(target), nogc)
        # If fakeobj works, result should be the same object
        assert result is target

    def test_fakeobj_primitive_returns_object(self):
        nogc = []
        fp = FakeobjPrimitive(nogc)
        target = [1, 2, 3]
        result = fp(addrof(target))
        assert result is target

    def test_fakeobj_primitive_reusable(self):
        nogc = []
        fp = FakeobjPrimitive(nogc)
        a = "hello_fakeobj"
        b = [42]
        assert fp(addrof(a)) is a
        assert fp(addrof(b)) is b

    def test_fakeobj_via_context(self):
        with Unsafe() as u:
            target = {"key": "value"}
            result = u.fakeobj(u.addrof(target))
            assert result is target
