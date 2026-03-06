"""Tests for core utility functions: p64a, u64, addrof, refbytes, sizeof, constants."""

import sys
import pytest
from unsafelib.core import (
    p64a, u64, addrof, refbytes, sizeof,
    BYTES_HEADER_LEN, TUPLE_HEADER_LEN, INT64_MAX, INT32_MAX, INT32_MIN,
    CodeType, FunctionType, nullfunc,
)


# --- p64a ---

class TestP64a:
    def test_zero(self):
        assert p64a(0) == [0] * 8

    def test_one_byte(self):
        assert p64a(0x41) == [0x41, 0, 0, 0, 0, 0, 0, 0]

    def test_multibyte(self):
        result = p64a(0x0102030405060708)
        assert result == [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]

    def test_max_64bit(self):
        result = p64a(0xFFFFFFFFFFFFFFFF)
        assert result == [0xFF] * 8

    def test_multiple_values(self):
        result = p64a(1, 2)
        assert len(result) == 16
        assert result[:8] == [1, 0, 0, 0, 0, 0, 0, 0]
        assert result[8:] == [2, 0, 0, 0, 0, 0, 0, 0]

    def test_three_values(self):
        result = p64a(0xAA, 0xBB, 0xCC)
        assert len(result) == 24

    def test_deadbeef(self):
        result = p64a(0xDEADBEEF)
        assert result == [0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0]


# --- u64 ---

class TestU64:
    def test_zero(self):
        assert u64([0] * 8) == 0

    def test_one_byte(self):
        assert u64([0x41, 0, 0, 0, 0, 0, 0, 0]) == 0x41

    def test_multibyte(self):
        assert u64([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]) == 0x0102030405060708

    def test_max(self):
        assert u64([0xFF] * 8) == 0xFFFFFFFFFFFFFFFF

    def test_roundtrip_small(self):
        for val in [0, 1, 255, 256, 0xFFFF, 0xDEAD]:
            assert u64(p64a(val)) == val

    def test_roundtrip_large(self):
        val = 0xDEADBEEFCAFEBABE
        assert u64(p64a(val)) == val

    def test_roundtrip_addresses(self):
        # typical heap addresses
        for val in [0x7F0000000000, 0x555555554000, 0x7FFFF7DD1000]:
            assert u64(p64a(val)) == val

    def test_single_byte_buffer(self):
        assert u64([42]) == 42

    def test_empty_buffer(self):
        assert u64([]) == 0


# --- addrof ---

class TestAddrof:
    def test_returns_id(self):
        obj = object()
        assert addrof(obj) == id(obj)

    def test_different_objects_different_addrs(self):
        a = object()
        b = object()
        assert addrof(a) != addrof(b)

    def test_same_object_same_addr(self):
        obj = [1, 2, 3]
        assert addrof(obj) == addrof(obj)

    def test_returns_int(self):
        assert isinstance(addrof(object()), int)

    def test_positive(self):
        assert addrof(object()) > 0

    def test_various_types(self):
        for obj in [42, "hello", b"bytes", [1], {}, (1,), None, True]:
            assert addrof(obj) == id(obj)


# --- refbytes ---

class TestRefbytes:
    def test_returns_address_past_header(self):
        nogc = []
        data = b"AAAABBBB"
        addr = refbytes(data, nogc)
        assert addr == id(data) + BYTES_HEADER_LEN

    def test_appends_to_nogc(self):
        nogc = []
        data = b"test"
        refbytes(data, nogc)
        assert data in nogc

    def test_different_data_different_addr(self):
        nogc = []
        a = b"AAAA"
        b_data = b"BBBB"
        assert refbytes(a, nogc) != refbytes(b_data, nogc)

    def test_consistent_for_same_object(self):
        nogc = []
        data = b"hello"
        assert refbytes(data, nogc) == refbytes(data, nogc)


# --- sizeof ---

class TestSizeof:
    def test_bytes_empty(self):
        # bytes header = sizeof(b"") - 1 (subtract the null terminator accounting)
        s = sizeof(b"")
        assert s > 0
        assert isinstance(s, int)

    def test_bytes_grows_with_content(self):
        assert sizeof(b"AAAA") > sizeof(b"")

    def test_tuple_empty(self):
        s = sizeof(())
        assert s > 0

    def test_tuple_grows(self):
        assert sizeof((1, 2, 3)) > sizeof(())

    def test_bytearray(self):
        assert sizeof(bytearray()) > 0


# --- constants ---

class TestConstants:
    def test_bytes_header_len_positive(self):
        assert BYTES_HEADER_LEN > 0

    def test_tuple_header_len_positive(self):
        assert TUPLE_HEADER_LEN > 0

    def test_int64_max(self):
        assert INT64_MAX == (1 << 63) - 1

    def test_int32_max(self):
        assert INT32_MAX == (1 << 31) - 1

    def test_int32_min(self):
        assert INT32_MIN == -(1 << 31)

    def test_codetype_is_code(self):
        assert CodeType is type((lambda: None).__code__)

    def test_functiontype_is_function(self):
        assert FunctionType is type(lambda: None)

    def test_nullfunc_callable(self):
        assert nullfunc() is None
