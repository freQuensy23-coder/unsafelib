"""
Context manager that gates all unsafe operations behind a `with` block.

Usage:
    with Unsafe() as u:
        addr = u.addrof(some_obj)
        mem = u.getmem()
        mem[addr:addr+8]  # read raw memory

    u.addrof(some_obj)  # raises UnsafeContextError
"""

from .exceptions import UnsafeContextError
from . import core


def _require_active(method):
    """Decorator that ensures the Unsafe context is active."""
    def wrapper(self, *args, **kwargs):
        if not self._active:
            raise UnsafeContextError(method.__name__)
        return method(self, *args, **kwargs)
    wrapper.__name__ = method.__name__
    wrapper.__doc__ = method.__doc__
    return wrapper


class Unsafe:
    """
    Context manager for memory-unsafe CPython operations.

    All unsafe primitives are only callable inside the `with` block.
    Attempting to use them outside raises UnsafeContextError.

    Supports CPython 3.8 - 3.11 only.
    """

    def __init__(self):
        self._active = False
        self._nogc = []          # prevent GC of forged objects
        self._fakeobj = None     # reusable fakeobj primitive
        self._mem = None         # cached memory view
        self._gadgets = None     # cached ROP gadgets

    def __enter__(self):
        self._active = True
        self._fakeobj = core.FakeobjPrimitive(self._nogc)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._active = False
        return False

    # --- primitives ---

    @_require_active
    def addrof(self, obj):
        """Return the heap address of a Python object."""
        return core.addrof(obj)

    @_require_active
    def fakeobj(self, addr):
        """Forge a Python object reference from an arbitrary address."""
        return self._fakeobj(addr)

    @_require_active
    def getmem(self):
        """
        Return a bytearray spanning the entire process virtual memory.
        Base address 0, length SSIZE_MAX. Cached after first call.
        """
        if self._mem is None:
            self._mem = core.make_getmem(self._fakeobj, self._nogc)
        return self._mem

    @_require_active
    def setrip(self, addr, rsi=tuple(), rdx=dict()):
        """Set RIP to an arbitrary address (calls it as tp_call)."""
        mem = self.getmem()
        return core.setrip(addr, self._fakeobj, self._nogc, mem, rsi=rsi, rdx=rdx)

    @_require_active
    def find_gadgets(self):
        """Search libc for ROP gadgets. Requires Linux /proc/self/maps."""
        if self._gadgets is None:
            mem = self.getmem()
            self._gadgets = core.find_gadgets(mem)
        return self._gadgets

    @_require_active
    def do_rop(self, payload):
        """Execute a ROP payload by pivoting the stack into it."""
        mem = self.getmem()
        gadgets = self.find_gadgets()
        return core.do_rop(payload, self._fakeobj, self._nogc, mem, gadgets)

    # --- utility re-exports ---

    @staticmethod
    def p64a(*n):
        """Pack 64-bit integers into a byte list (little-endian). Safe to call anytime."""
        return core.p64a(*n)

    @staticmethod
    def u64(buf):
        """Unpack little-endian bytes to int. Safe to call anytime."""
        return core.u64(buf)

    @_require_active
    def refbytes(self, data):
        """Get the address of the internal buffer of a bytes object."""
        return core.refbytes(data, self._nogc)
