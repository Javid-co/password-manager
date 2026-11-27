"""Storage layer: reads and writes the vault file.

It only handles bytes, paths, permissions and safe writing. It does not know
what is inside the vault. See docs/design.md, threats V5, V6, V7, I2, A1-A4.
"""

import json
import os
import stat
import tempfile
import unicodedata

from . import access, audit
from .errors import PwmError

DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".pwmanager")
DEFAULT_PATH = os.path.join(DEFAULT_DIR, "vault.json")

# A real vault with a few hundred entries is far below this. The limit stops
# the program from reading a huge file into memory.
MAX_VAULT_SIZE = 10 * 1024 * 1024
MAX_PATH_LEN = 4096

IS_POSIX = os.name == "posix"


class StorageError(PwmError):
    pass


class VaultNotFound(StorageError):
    pass


def resolve_path(path=None):
    """Turn a user-given vault path into a checked absolute path (I2).

    realpath removes any "..", so the path that is checked is the path that
    is used. Control characters are refused, so the path is safe to print.
    """
    if path is None:
        path = DEFAULT_PATH
    if (not isinstance(path, str) or not path or len(path) > MAX_PATH_LEN
            or any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in path)):
        raise StorageError("invalid vault path")
    full = os.path.realpath(os.path.expanduser(path))
    if not full.lower().endswith(".json"):
        raise StorageError("vault path must end in .json")
    if os.path.isdir(full):
        raise StorageError("vault path is a folder")
    return full


def _check_not_symlink(path):
    """Refuse to work with a path that is a symlink (V7)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode):
        raise StorageError("refusing to use a symlink: " + path)
    return st


def _same_path(a, b):
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def _fixed(fixed, what):
    if fixed:
        audit.event("access.fixed", file=what)


def ensure_dir(path):
    """Create the folder that holds the vault, private to the user (V5, A2).

    A folder we create, and the default ~/.pwmanager, are made private (0700
    or a private ACL). A folder the user chose that already exists is left
    as it is, because it may be their home folder or Desktop. The files
    inside it are still private.
    """
    folder = os.path.dirname(path)
    st = _check_not_symlink(folder)
    if st is None:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        access.make_private_dir(folder)
    elif not stat.S_ISDIR(st.st_mode):
        raise StorageError("vault folder is not a folder: " + folder)
    elif _same_path(folder, DEFAULT_DIR):
        _fixed(access.check_dir(folder), "folder")


def exists(path):
    return _check_not_symlink(path) is not None


def read_vault(path):
    """Read and parse the vault file. Returns the JSON document (a dict)."""
    st = _check_not_symlink(path)
    if st is None:
        raise VaultNotFound("no vault found at " + path + " (run 'pwm init' first)")
    if not stat.S_ISREG(st.st_mode):
        raise StorageError("vault is not a regular file")
    if st.st_size > MAX_VAULT_SIZE:
        raise StorageError("vault file is too large")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise StorageError("could not open vault file") from None
    with os.fdopen(fd, "rb") as f:
        # A2: checked on the open file, so it is the file we really read.
        _fixed(access.check_file(path, f.fileno()), "vault")
        # Read one byte more than the limit, in case the file grew after lstat.
        data = f.read(MAX_VAULT_SIZE + 1)
    if len(data) > MAX_VAULT_SIZE:
        raise StorageError("vault file is too large")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        # Same message as a wrong password, see M5.
        raise StorageError("could not unlock vault") from None
    if not isinstance(doc, dict):
        raise StorageError("could not unlock vault")
    return doc


def write_vault(path, doc):
    """Write the vault atomically (V6).

    The data goes to a temp file in the same folder first. mkstemp creates it
    with O_CREAT | O_EXCL (V7), and it is made private (0600 or a private
    ACL) before anything is written to it. After fsync it replaces the old
    vault with os.replace, so a crash never leaves a half-written vault.
    """
    ensure_dir(path)
    if _check_not_symlink(path) is not None:
        # A1: never replace a vault that belongs to another user.
        _fixed(access.check_file(path), "vault")
    folder = os.path.dirname(path)
    data = json.dumps(doc, indent=2).encode("utf-8")

    fd, tmp = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=folder)
    try:
        access.make_private_file(tmp, fd)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    if IS_POSIX:
        # fsync the folder too, so the rename itself is saved to disk.
        dir_fd = os.open(folder, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


class VaultLock:
    """An exclusive lock on <vault>.lock while a command uses the vault.

    Without it, two pwm commands running at the same time could both load
    the vault, change it, and save. The second save would silently drop the
    first one's change. The lock is held from unlock until the vault is
    locked again. The OS releases it if the process dies, so there are no
    stale locks.
    """

    def __init__(self, vault_path):
        self.path = vault_path + ".lock"
        self._fd = None

    def acquire(self):
        if self._fd is not None:
            return
        try:
            fd, fixed = access.open_private(self.path, os.O_RDWR)
        except OSError:
            raise StorageError("could not open the lock file " + self.path) from None
        _fixed(fixed, "lock")
        try:
            _lock_fd(fd)
        except OSError:
            os.close(fd)
            raise StorageError(
                "the vault is being used by another pwm command, try again") from None
        self._fd = fd

    def release(self):
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            _unlock_fd(fd)
        except OSError:
            pass
        finally:
            os.close(fd)


if IS_POSIX:
    import fcntl

    def _lock_fd(fd):
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock_fd(fd):
        fcntl.flock(fd, fcntl.LOCK_UN)

else:
    import msvcrt

    def _lock_fd(fd):
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock_fd(fd):
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
