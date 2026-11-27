"""User management: create, unlock, save and lock the vault.

The vault only opens if AES-GCM decryption with the key from the master
password works. No password hash is stored anywhere.

Every record operation (list, read, add, update, delete, save) goes through
_authorize() first. It refuses when the vault is locked, or when the process
is not running as the same OS user that unlocked it (A3). Every field goes
through the validate module here as well as in the CLI, so the rules can't
be skipped by calling the vault directly (I1). Each operation is logged
without any names or values (L1).

Memory (R1): the key is a SecretBytes. The vault keeps its own private copy
of every string it stores, so lock() can overwrite all of them with zeros
without touching strings that other code still uses.
"""

import datetime

from . import access, audit, crypto, storage, validate
from .crypto import VaultError
from .errors import PwmError
from .secmem import private_copy, wipe

MIN_MASTER_LEN = validate.MIN_MASTER_LEN


class EntryError(PwmError):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _wipe_entry(entry):
    for field in validate.ENTRY_FIELDS:
        value = entry.get(field)
        if isinstance(value, str):
            wipe(value)
    entry.clear()


def _wipe_entries(entries):
    names = list(entries)
    for entry in entries.values():
        if isinstance(entry, dict):
            _wipe_entry(entry)
    entries.clear()
    for name in names:
        if isinstance(name, str):
            wipe(name)


class Vault:
    """An unlocked vault. Use it in a with block so it is locked at the end."""

    def __init__(self, path, key, salt, params, entries, file_lock):
        self.path = path
        self._key = key  # SecretBytes
        self._salt = salt
        self._params = dict(params)
        self._entries = entries
        self._file_lock = file_lock
        self._owner = access.current_user()

    # ------------------------------------------------------------ open / close

    @classmethod
    def create(cls, path, master_password):
        """Make a new empty vault. Refuses to overwrite an existing one (I6)."""
        validate.master_password(master_password)
        if storage.exists(path):
            raise storage.StorageError("a vault already exists at " + path)
        storage.ensure_dir(path)
        file_lock = storage.VaultLock(path)
        file_lock.acquire()
        key = None
        try:
            if storage.exists(path):  # created by another command meanwhile
                raise storage.StorageError("a vault already exists at " + path)
            salt = crypto.new_salt()
            params = crypto.DEFAULT_KDF_PARAMS
            key = crypto.derive_key(master_password, salt, params)
            vault = cls(path, key, salt, params, {}, file_lock)
            vault.save()
        except BaseException:
            if key is not None:
                key.wipe()
            file_lock.release()
            raise
        audit.event("vault.init")
        return vault

    @classmethod
    def unlock(cls, path, master_password):
        """Open the vault. Raises VaultError for a wrong password or changed file."""
        if not storage.exists(path):
            raise storage.VaultNotFound("no vault found at " + path + " (run 'pwm init' first)")
        file_lock = storage.VaultLock(path)
        file_lock.acquire()
        try:
            doc = storage.read_vault(path)
            try:
                key, salt, params, payload = crypto.decrypt_vault(master_password, doc)
            except VaultError:
                audit.event("vault.unlock", "fail", reason="bad_password_or_changed_file")
                raise
            try:
                validate.payload(payload)
            except validate.ValidationError:
                key.wipe()
                if isinstance(payload.get("entries"), dict):
                    _wipe_entries(payload["entries"])
                audit.event("vault.unlock", "fail", reason="invalid_contents")
                raise VaultError() from None
        except BaseException:
            file_lock.release()
            raise
        audit.event("vault.unlock")
        return cls(path, key, salt, params, payload["entries"], file_lock)

    def lock(self):
        """Wipe the key and every stored string, then release the file lock."""
        if self._key is not None:
            self._key.wipe()
            self._key = None
        _wipe_entries(self._entries)
        if self._file_lock is not None:
            self._file_lock.release()
            self._file_lock = None

    @property
    def is_locked(self):
        return self._key is None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.lock()
        return False

    def __del__(self):
        # Last chance to wipe if someone forgot lock(). __del__ must not raise.
        try:
            self.lock()
        except Exception:  # nosec B110
            pass

    # ------------------------------------------------------------ access control

    def _authorize(self):
        """A3: checked at the start of every record operation."""
        if self._key is None or self._key.wiped:
            raise access.AccessDenied("the vault is locked")
        if access.current_user() != self._owner:
            raise access.AccessDenied("the vault was unlocked by a different user")

    def _find(self, name):
        validate.entry_name(name)
        if name not in self._entries:
            raise EntryError(f"no entry called '{name}'")
        return self._entries[name]

    # ------------------------------------------------------------ record operations

    def exists(self, name):
        self._authorize()
        return validate.entry_name(name) in self._entries

    def names(self):
        """Sorted list of (name, username). Never includes passwords."""
        self._authorize()
        rows = sorted((name, e["username"]) for name, e in self._entries.items())
        audit.event("entry.list", count=len(rows))
        return rows

    def get(self, name):
        """A shallow copy of one record. The strings in it are wiped on lock,
        so use them before the vault is locked."""
        self._authorize()
        entry = dict(self._find(name))
        audit.event("entry.read")
        return entry

    def add(self, name, username, password, notes):
        self._authorize()
        validate.entry_name(name)
        username = validate.username(username)
        password = validate.password(password)
        notes = validate.notes(notes)
        if name in self._entries:
            raise EntryError(f"an entry called '{name}' already exists (use update)")
        if len(self._entries) >= validate.MAX_ENTRIES:
            raise EntryError("the vault is full")
        now = _now()
        self._entries[private_copy(name)] = {
            "username": private_copy(username),
            "password": private_copy(password),
            "notes": private_copy(notes),
            "created": now,
            "modified": now,
        }
        audit.event("entry.add")

    def update(self, name, **fields):
        self._authorize()
        entry = self._find(name)
        new = {}
        for field, value in fields.items():
            if field not in validate.ENTRY_FIELDS:
                raise validate.ValidationError("unknown field")
            if value is not None:
                new[field] = validate.field(field, value)
        for field, value in new.items():
            wipe(entry[field])
            entry[field] = private_copy(value)
        entry["modified"] = _now()
        audit.event("entry.update")

    def delete(self, name):
        self._authorize()
        entry = self._find(name)
        key = next(k for k in self._entries if k == name)
        del self._entries[key]
        _wipe_entry(entry)
        wipe(key)
        audit.event("entry.delete")

    def save(self):
        self._authorize()
        doc = crypto.encrypt_vault(self._key, self._salt, self._params,
                                   {"entries": self._entries})
        storage.write_vault(self.path, doc)
        audit.event("vault.save")

    def change_master(self, new_password):
        """New salt, new key, and everything encrypted again."""
        self._authorize()
        validate.master_password(new_password, "new master password")
        salt = crypto.new_salt()
        key = crypto.derive_key(new_password, salt, crypto.DEFAULT_KDF_PARAMS)
        old = (self._key, self._salt, self._params)
        self._key, self._salt = key, salt
        self._params = dict(crypto.DEFAULT_KDF_PARAMS)
        try:
            self.save()
        except BaseException:
            # The old vault file is still there, so go back to the old key.
            key.wipe()
            self._key, self._salt, self._params = old
            audit.event("master.change", "fail")
            raise
        old[0].wipe()
        audit.event("master.change")
