import json

import pytest

from pwmanager import storage
from pwmanager.crypto import VaultError
from pwmanager.vault import Vault

MASTER = "a long master password"


@pytest.fixture
def path(tmp_path):
    return storage.resolve_path(str(tmp_path / "vault.json"))


def test_create_and_unlock(path):
    with Vault.create(path, MASTER) as v:
        v.add("github", "javid", "pw123", "")
        v.save()
    with Vault.unlock(path, MASTER) as v:
        assert v.get("github")["password"] == "pw123"


def test_wrong_master_password(path):
    Vault.create(path, MASTER).lock()
    with pytest.raises(VaultError, match="could not unlock vault"):
        Vault.unlock(path, "not the password")


def test_short_master_password(path):
    with pytest.raises(ValueError):
        Vault.create(path, "short")


def test_init_does_not_overwrite(path):
    Vault.create(path, MASTER).lock()
    with pytest.raises(storage.StorageError):
        Vault.create(path, MASTER)


def test_no_password_hash_or_plaintext_on_disk(path):
    with Vault.create(path, MASTER) as v:
        v.add("bank", "me", "TopSecret!", "pin 1234")
        v.save()
    text = open(path, encoding="utf-8").read()
    for secret in ("TopSecret!", "bank", "pin 1234", MASTER):
        assert secret not in text


def test_lock_wipes_key(path):
    v = Vault.create(path, MASTER)
    key = v._key
    v.lock()
    assert key == bytearray(len(key))
    assert v.entries == {}
    with pytest.raises(VaultError):
        v.save()


def test_add_get_update_delete(path):
    with Vault.create(path, MASTER) as v:
        v.add("a", "u", "p", "n")
        with pytest.raises(KeyError):
            v.add("a", "u", "p", "n")
        v.update("a", password="p2", username=None)
        assert v.get("a")["password"] == "p2"
        assert v.get("a")["username"] == "u"
        v.delete("a")
        with pytest.raises(KeyError):
            v.get("a")


def test_change_master(path):
    with Vault.create(path, MASTER) as v:
        v.add("a", "u", "p", "")
        v.save()
        old_salt = json.load(open(path))["header"]["salt"]
        v.change_master("a different long password")
    assert json.load(open(path))["header"]["salt"] != old_salt
    with pytest.raises(VaultError):
        Vault.unlock(path, MASTER)
    with Vault.unlock(path, "a different long password") as v:
        assert v.get("a")["password"] == "p"


def test_bad_payload_shape_refused(path, monkeypatch):
    # Even a correctly encrypted vault must have the expected structure.
    from pwmanager import crypto

    with Vault.create(path, MASTER) as v:
        doc = crypto.encrypt_vault(bytes(v._key), v._salt, v._params, {"entries": []})
    storage.write_vault(path, doc)
    with pytest.raises(VaultError):
        Vault.unlock(path, MASTER)
