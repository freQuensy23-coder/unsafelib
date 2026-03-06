"""Tests for the Unsafe context manager gating logic."""

import pytest
from unsafelib import Unsafe, UnsafeContextError


def test_addrof_outside_context_raises():
    u = Unsafe()
    with pytest.raises(UnsafeContextError, match="addrof"):
        u.addrof(object())


def test_getmem_outside_context_raises():
    u = Unsafe()
    with pytest.raises(UnsafeContextError, match="getmem"):
        u.getmem()


def test_fakeobj_outside_context_raises():
    u = Unsafe()
    with pytest.raises(UnsafeContextError, match="fakeobj"):
        u.fakeobj(0)


def test_setrip_outside_context_raises():
    u = Unsafe()
    with pytest.raises(UnsafeContextError, match="setrip"):
        u.setrip(0)


def test_do_rop_outside_context_raises():
    u = Unsafe()
    with pytest.raises(UnsafeContextError, match="do_rop"):
        u.do_rop([])


def test_find_gadgets_outside_context_raises():
    u = Unsafe()
    with pytest.raises(UnsafeContextError, match="find_gadgets"):
        u.find_gadgets()


def test_refbytes_outside_context_raises():
    u = Unsafe()
    with pytest.raises(UnsafeContextError, match="refbytes"):
        u.refbytes(b"hello")


def test_methods_blocked_after_exit():
    u = Unsafe()
    with u:
        pass  # context is now closed
    with pytest.raises(UnsafeContextError):
        u.addrof(object())


def test_addrof_works_inside_context():
    with Unsafe() as u:
        obj = object()
        assert u.addrof(obj) == id(obj)


def test_p64a_works_anytime():
    # p64a is a static utility, should work without context
    result = Unsafe.p64a(0x41)
    assert result == [0x41, 0, 0, 0, 0, 0, 0, 0]


def test_u64_works_anytime():
    result = Unsafe.u64([0x41, 0, 0, 0, 0, 0, 0, 0])
    assert result == 0x41


def test_u64_roundtrip():
    val = 0xDEADBEEFCAFEBABE
    packed = Unsafe.p64a(val)
    assert Unsafe.u64(packed) == val
