# unsafe-python

Memory-unsafe operations in pure CPython, gated behind safe context managers. No `ctypes`, no C extensions.

CPython 3.8 - 3.11 only.

## Installation

```bash
pip install -U unsafelib
```

## Usage

```python
from unsafelib import Unsafe

# All unsafe ops require a context block
with Unsafe() as u:
    # Get heap address of any Python object
    obj = [1, 2, 3]
    print(hex(u.addrof(obj)))  # 0x7f2a1c3d4e80

    # Read/write raw process memory
    mem = u.getmem()
    print(bytes(mem[u.addrof(obj):u.addrof(obj) + 32]))

    # Forge a fake object from an address
    clone = u.fakeobj(u.addrof(obj))
    assert clone is obj

    # Jump to arbitrary address (segfaults)
    u.setrip(0xDEADBEEF)

# Outside the block - raises UnsafeContextError
u.getmem()  # UnsafeContextError: Cannot call 'getmem' outside of an unsafe context.
```

## License

MIT
