"""
unsafe-python: Memory-unsafe operations in pure CPython, gated behind context managers.

Usage:
    from unsafe_python import Unsafe

    with Unsafe() as u:
        mem = u.getmem()
        mem[u.addrof(mem):u.addrof(mem) + 0x40]
"""

from .context import Unsafe
from .exceptions import UnsafeContextError, UnsafeError, HeapGroomError, GadgetSearchError
from .core import p64a, u64

__all__ = [
    "Unsafe",
    "UnsafeError",
    "UnsafeContextError",
    "HeapGroomError",
    "GadgetSearchError",
    "p64a",
    "u64",
]
