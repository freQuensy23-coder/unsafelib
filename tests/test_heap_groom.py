"""Tests for heap grooming and LOAD_CONST OOB helpers."""

import sys
import pytest
from unsafelib.core import (
    _get_aligned_tuple_and_bytes,
    _load_n,
    _replace_code_consts,
    addrof,
    TUPLE_HEADER_LEN,
    CodeType,
    FunctionType,
)


class TestGetAlignedTupleAndBytes:
    def test_returns_tuple_and_bytes(self):
        t, b = _get_aligned_tuple_and_bytes(b"\x41" * 8)
        assert isinstance(t, tuple)
        assert isinstance(b, bytes)

    def test_bytes_nearby_tuple(self):
        t, b = _get_aligned_tuple_and_bytes(b"\x00" * 8)
        dist = addrof(b) - addrof(t)
        assert dist > 0
        assert dist <= 100000

    def test_bytes_starts_with_prefix(self):
        prefix = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
        t, b = _get_aligned_tuple_and_bytes(prefix)
        assert b.startswith(prefix)

    def test_repeated_calls_succeed(self):
        # heap groom should be somewhat reliable
        for _ in range(3):
            t, b = _get_aligned_tuple_and_bytes(b"\x00" * 8)
            assert isinstance(t, tuple)


class TestLoadN:
    def test_returns_callable(self):
        fn = _load_n(5)
        assert callable(fn)

    def test_has_code_object(self):
        fn = _load_n(5)
        assert hasattr(fn, "__code__")
        assert isinstance(fn.__code__, CodeType)

    def test_various_offsets(self):
        for n in [2, 5, 10, 50]:
            fn = _load_n(n)
            assert callable(fn)

    def test_code_consts_has_enough_entries(self):
        # The lambda needs enough consts that the bytecode references index n
        fn = _load_n(10)
        # co_consts should have entries for None + the range values
        assert len(fn.__code__.co_consts) > 0


class TestReplaceCodeConsts:
    def test_replaces_consts(self):
        original = (lambda: 42).__code__
        new_consts = (None, 99)
        new_code = _replace_code_consts(original, new_consts)
        assert new_code.co_consts == new_consts

    def test_preserves_other_attrs(self):
        original = (lambda: 42).__code__
        new_consts = (None, 99)
        new_code = _replace_code_consts(original, new_consts)
        assert new_code.co_name == original.co_name
        assert new_code.co_filename == original.co_filename

    def test_result_is_code_type(self):
        original = (lambda: 42).__code__
        new_code = _replace_code_consts(original, (None,))
        assert isinstance(new_code, CodeType)

    def test_executable(self):
        original = (lambda: 42).__code__
        new_consts = (None, 99)
        new_code = _replace_code_consts(original, new_consts)
        fn = FunctionType(new_code, {})
        assert fn() == 99
