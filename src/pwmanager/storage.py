"""Storage layer: reads and writes the vault file.

It only handles bytes, paths, permissions and safe writing. It does not know
what is inside the vault. See docs/design.md, threats V5, V6, V7 and I2.
"""

import json
import os
import stat
import tempfile

DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".pwmanager")
DEFAULT_PATH = os.path.join(DEFAULT_DIR, "vault.json")

# A real vault with a few hundred entries is far below this. The limit stops
# the program from reading a huge file into memory.
MAX_VAULT_SIZE = 10 * 1024 * 1024

IS_POSIX = os.name == "posix"


class StorageError(Exception):
    pass


class VaultNotFound(StorageError):
    pass


def resolve_path(path=None):
    """Turn a user-given vault path into a checked absolute path (I2)."""
    if path is None:
        path = DEFAULT_PATH
    if not isinstance(path, str) or not path or "\x00" in path or len(path) > 4096:
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


def ensure_dir(path):
    """Create the folder that holds the vault with mode 0700 (V5)."""
    folder = os.path.dirname(path)
    st = _check_not_symlink(folder)
    if st is None:
        os.makedirs(folder, mode=0o700, exist_ok=True)
    elif not stat.S_ISDIR(st.st_mode):
        raise StorageError("vault folder is not a folder: " + folder)
    if IS_POSIX:
        os.chmod(folder, 0o700)


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
    except OSError as e:
        raise StorageError("could not open vault file") from e
    with os.fdopen(fd, "rb") as f:
        # Read one byte more than the limit, in case the file grew after lstat.
        data = f.read(MAX_VAULT_SIZE + 1)
    if len(data) > MAX_VAULT_SIZE:
        raise StorageError("vault file is too large")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Same message as a wrong password, see M5.
        raise StorageError("could not unlock vault") from None
    if not isinstance(doc, dict):
        raise StorageError("could not unlock vault")
    return doc


def write_vault(path, doc):
    """Write the vault atomically (V6).

    The data goes to a temp file in the same folder first. mkstemp creates it
    with O_CREAT | O_EXCL and mode 0600 (V7, V5). After fsync it replaces the
    old vault with os.replace, so a crash never leaves a half-written vault.
    """
    ensure_dir(path)
    _check_not_symlink(path)
    folder = os.path.dirname(path)
    data = json.dumps(doc, indent=2).encode("utf-8")

    fd, tmp = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=folder)
    try:
        if IS_POSIX:
            os.fchmod(fd, 0o600)
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
