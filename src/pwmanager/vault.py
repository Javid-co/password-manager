"""User management: create, unlock, save and lock the vault.

The vault only opens if AES-GCM decryption with the key from the master
password works. No password hash is stored anywhere.
"""

import datetime

from . import crypto, storage
from .crypto import VaultError

MIN_MASTER_LEN = 12
MAX_MASTER_LEN = 1024


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_master_password(password):
    """M1: the master password must be at least 12 characters."""
    if len(password) < MIN_MASTER_LEN:
        raise ValueError(f"master password must be at least {MIN_MASTER_LEN} characters")
    if len(password) > MAX_MASTER_LEN:
        raise ValueError(f"master password must be at most {MAX_MASTER_LEN} characters")


def _check_payload(payload):
    entries = payload.get("entries")
    if set(payload) != {"entries"} or not isinstance(entries, dict):
        raise VaultError()
    for entry in entries.values():
        if not isinstance(entry, dict):
            raise VaultError()


class Vault:
    """An unlocked vault. Use it in a with block so the key is wiped at the end."""

    def __init__(self, path, key, salt, params, entries):
        self.path = path
        # R1: kept in a bytearray so it can be overwritten with zeros later.
        self._key = bytearray(key)
        self._salt = salt
        self._params = dict(params)
        self.entries = entries

    @classmethod
    def create(cls, path, master_password):
        """Make a new empty vault. Refuses to overwrite an existing one (I6)."""
        check_master_password(master_password)
        if storage.exists(path):
            raise storage.StorageError("a vault already exists at " + path)
        salt = crypto.new_salt()
        params = crypto.DEFAULT_KDF_PARAMS
        key = crypto.derive_key(master_password, salt, params)
        vault = cls(path, key, salt, params, {})
        vault.save()
        return vault

    @classmethod
    def unlock(cls, path, master_password):
        """Open the vault. Raises VaultError for a wrong password or changed file."""
        doc = storage.read_vault(path)
        key, salt, params, payload = crypto.decrypt_vault(master_password, doc)
        _check_payload(payload)
        return cls(path, key, salt, params, payload["entries"])

    def save(self):
        if self._key is None:
            raise VaultError("vault is locked")
        doc = crypto.encrypt_vault(bytes(self._key), self._salt, self._params,
                                   {"entries": self.entries})
        storage.write_vault(self.path, doc)

    def change_master(self, new_password):
        """New salt, new key, and everything encrypted again."""
        check_master_password(new_password)
        salt = crypto.new_salt()
        key = crypto.derive_key(new_password, salt, crypto.DEFAULT_KDF_PARAMS)
        old = (self._key, self._salt, self._params)
        self._key = bytearray(key)
        self._salt = salt
        self._params = dict(crypto.DEFAULT_KDF_PARAMS)
        try:
            self.save()
        except BaseException:
            # The old vault file is still there, so go back to the old key.
            self.lock_key()
            self._key, self._salt, self._params = old
            raise
        for i in range(len(old[0])):
            old[0][i] = 0

    def add(self, name, username, password, notes):
        if name in self.entries:
            raise KeyError(f"an entry called '{name}' already exists (use update)")
        now = _now()
        self.entries[name] = {
            "username": username,
            "password": password,
            "notes": notes,
            "created": now,
            "modified": now,
        }

    def get(self, name):
        if name not in self.entries:
            raise KeyError(f"no entry called '{name}'")
        return self.entries[name]

    def update(self, name, **fields):
        entry = self.get(name)
        for field, value in fields.items():
            if field not in ("username", "password", "notes"):
                raise ValueError("unknown field " + field)
            if value is not None:
                entry[field] = value
        entry["modified"] = _now()

    def delete(self, name):
        self.get(name)
        del self.entries[name]

    def lock_key(self):
        if self._key is not None:
            for i in range(len(self._key)):
                self._key[i] = 0
            self._key = None

    def lock(self):
        """Wipe the key and drop the entries (R1, only partly possible in Python)."""
        self.lock_key()
        self.entries = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.lock()
        return False
