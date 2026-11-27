"""Secure memory helpers (R1, R2).

Python does not let a program free or overwrite memory directly, so this
module does what is possible:

- SecretBytes keeps a secret (the vault key) in one fixed buffer. The pages
  are locked in RAM if the OS allows it, so they are not written to the swap
  file, and the buffer is overwritten with zeros when it is wiped.
- wipe() overwrites a bytes or str object in place. bytes and str are
  immutable in Python, so this writes straight into the object's memory with
  ctypes. It only works on CPython and only for ASCII strings, so it returns
  False when it cannot wipe something.

Only call wipe() on objects that this program created itself and that
nothing else uses. Wiping a string constant from the code or a cached
one-character string would break the interpreter, so strings shorter than
2 characters are never touched.
"""

import ctypes
import os
import sys

_CPYTHON = sys.implementation.name == "cpython"

# ---------------------------------------------------------------- page locking

if os.name == "nt":
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _kernel32.VirtualLock.restype = ctypes.c_int
    _kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _kernel32.VirtualUnlock.restype = ctypes.c_int

    def _lock_pages(addr, size):
        return bool(_kernel32.VirtualLock(addr, size))

    def _unlock_pages(addr, size):
        _kernel32.VirtualUnlock(addr, size)

else:
    try:
        _libc = ctypes.CDLL(None, use_errno=True)
        _libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    except (OSError, AttributeError):
        _libc = None

    def _lock_pages(addr, size):
        # mlock can fail if RLIMIT_MEMLOCK is low. It is only an extra layer,
        # so the program keeps working without it.
        return _libc is not None and _libc.mlock(addr, size) == 0

    def _unlock_pages(addr, size):
        if _libc is not None:
            _libc.munlock(addr, size)


# ---------------------------------------------------------------- SecretBytes

class SecretBytes:
    """A fixed-size secret buffer that is locked in RAM and wiped after use.

    Use buffer() to pass it to a library. Never turn it into bytes(), that
    would make a copy that cannot be wiped.
    """

    __slots__ = ("_buf", "_cbuf", "_locked")

    def __init__(self, size):
        if not isinstance(size, int) or size <= 0:
            raise ValueError("size must be a positive int")
        self._buf = bytearray(size)
        # A ctypes view over the same memory, to get its address. While it
        # exists the bytearray cannot be resized, so it never moves.
        self._cbuf = (ctypes.c_char * size).from_buffer(self._buf)
        self._locked = _lock_pages(ctypes.addressof(self._cbuf), size)

    @classmethod
    def from_bytes(cls, data):
        """Copy data into a new SecretBytes. The caller should wipe data."""
        secret = cls(len(data))
        secret._buf[:] = data
        return secret

    @property
    def locked_in_ram(self):
        return self._locked

    @property
    def wiped(self):
        return self._buf is None

    def buffer(self):
        if self._buf is None:
            raise ValueError("secret was already wiped")
        return self._buf

    def wipe(self):
        if self._buf is None:
            return
        size = len(self._buf)
        addr = ctypes.addressof(self._cbuf)
        ctypes.memset(addr, 0, size)
        if self._locked:
            _unlock_pages(addr, size)
            self._locked = False
        self._cbuf = None
        self._buf = None

    def __len__(self):
        return 0 if self._buf is None else len(self._buf)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.wipe()
        return False

    def __del__(self):
        # __del__ must not raise (it can run while Python is shutting down).
        try:
            self.wipe()
        except Exception:  # nosec B110
            pass

    def __repr__(self):
        return "<SecretBytes hidden>"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("SecretBytes cannot be pickled")


# ---------------------------------------------------------------- wipe()

def _data_address(obj):
    # For bytes and compact ASCII str objects in CPython, the characters are
    # stored at the end of the object, followed by one NUL byte.
    return id(obj) + sys.getsizeof(obj) - len(obj) - 1


def wipe(obj):
    """Overwrite obj with zeros in place. Returns True if it was wiped."""
    if isinstance(obj, SecretBytes):
        obj.wipe()
        return True
    if isinstance(obj, bytearray):
        obj[:] = bytes(len(obj))
        return True
    if isinstance(obj, memoryview):
        if obj.readonly:
            return False
        obj[:] = bytes(obj.nbytes)
        return True
    if type(obj) not in (bytes, str) or not _CPYTHON or len(obj) < 2:
        return False
    if type(obj) is str and not obj.isascii():
        # Non-ASCII strings use a different layout, so they are left alone.
        return False
    ctypes.memset(_data_address(obj), 0, len(obj))
    return True


def wipe_all(*objs):
    for obj in objs:
        if obj is not None:
            wipe(obj)


def private_copy(text):
    """Return a new str with the same value that only the caller owns.

    The vault keeps its own copies of every field, so wiping them on lock
    can never change a string that some other code is still using.
    """
    if not isinstance(text, str):
        raise TypeError("expected str")
    if len(text) < 2:
        return text  # cached by Python, never wiped
    data = text.encode("utf-8")
    copy = data.decode("utf-8")
    wipe(data)
    return copy
