class UnsafeError(Exception):
    """Base exception for unsafe-python."""


class UnsafeContextError(UnsafeError):
    """Raised when unsafe operations are used outside of an Unsafe() context block."""

    def __init__(self, method_name: str = ""):
        if method_name:
            msg = (
                f"Cannot call '{method_name}' outside of an unsafe context. "
                f"Use: with Unsafe() as u: u.{method_name}(...)"
            )
        else:
            msg = "Unsafe operations are only allowed inside a 'with Unsafe() as u:' block."
        super().__init__(msg)


class HeapGroomError(UnsafeError):
    """Raised when heap grooming fails to align tuple and bytes objects."""

    def __init__(self, distance_hex: str):
        super().__init__(
            f"Heap groom failed: could not allocate bytes near enough to tuple "
            f"(distance: {distance_hex})"
        )


class GadgetSearchError(UnsafeError):
    """Raised when ROP gadget search fails."""

    def __init__(self, detail: str = ""):
        msg = "ROP gadget search failed"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)
