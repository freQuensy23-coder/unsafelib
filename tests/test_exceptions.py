"""Tests for custom exceptions."""

import pytest
from unsafelib.exceptions import (
    UnsafeError,
    UnsafeContextError,
    HeapGroomError,
    GadgetSearchError,
)


class TestUnsafeError:
    def test_is_exception(self):
        assert issubclass(UnsafeError, Exception)

    def test_raise(self):
        with pytest.raises(UnsafeError):
            raise UnsafeError("test")


class TestUnsafeContextError:
    def test_is_unsafe_error(self):
        assert issubclass(UnsafeContextError, UnsafeError)

    def test_message_with_method(self):
        err = UnsafeContextError("getmem")
        assert "getmem" in str(err)
        assert "with Unsafe()" in str(err)

    def test_message_without_method(self):
        err = UnsafeContextError()
        assert "with Unsafe()" in str(err)

    def test_includes_usage_hint(self):
        err = UnsafeContextError("fakeobj")
        msg = str(err)
        assert "u.fakeobj(...)" in msg


class TestHeapGroomError:
    def test_is_unsafe_error(self):
        assert issubclass(HeapGroomError, UnsafeError)

    def test_message(self):
        err = HeapGroomError("0xdeadbeef")
        assert "0xdeadbeef" in str(err)
        assert "Heap groom failed" in str(err)


class TestGadgetSearchError:
    def test_is_unsafe_error(self):
        assert issubclass(GadgetSearchError, UnsafeError)

    def test_message_with_detail(self):
        err = GadgetSearchError("libc not found")
        assert "libc not found" in str(err)

    def test_message_without_detail(self):
        err = GadgetSearchError()
        assert "ROP gadget search failed" in str(err)
