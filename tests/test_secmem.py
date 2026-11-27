"""Memory handling checks (R1): secrets are wiped after use."""

import os
import pickle

import pytest
from conftest import MASTER, add

from pwmanager import cli, crypto, storage
from pwmanager.secmem import SecretBytes, private_copy, wipe
from pwmanager.vault import Vault


def zeroed(value):
    return len(value) > 0 and set(value) <= {0, "\x00"}


# ---------------------------------------------------------------- wipe()

def test_wipe_bytes():
    b = "secret-key-bytes".encode()
    assert wipe(b)
    assert b == bytes(16)


def test_wipe_ascii_str():
    s = private_copy("hunter2-password")
    assert wipe(s)
    assert s == "\x00" * 16


def test_wipe_bytearray_and_memoryview():
    ba = bytearray(b"secret")
    assert wipe(ba) and ba == bytearray(6)
    ba = bytearray(b"secret")
    assert wipe(memoryview(ba)) and ba == bytearray(6)
    assert not wipe(memoryview(b"readonly"))


def test_wipe_leaves_what_it_cannot_safely_change():
    # One-character strings are shared by all of Python.
    assert not wipe("a")
    assert "a" == chr(97)
    # Non-ASCII strings have a different layout.
    s = private_copy("pässwörd")
    assert not wipe(s)
    assert s == "pässwörd"

    class MyBytes(bytes):
        pass

    for other in (123, None, MyBytes(b"abc"), ["list"]):
        assert not wipe(other)


def test_private_copy_is_a_new_object():
    s = "".join(["abc", "def"])
    c = private_copy(s)
    assert c == s and c is not s
    wipe(c)
    assert s == "abcdef"


# ---------------------------------------------------------------- SecretBytes

def test_secret_bytes_wipe():
    sb = SecretBytes.from_bytes(b"\x41" * 32)
    buf = sb.buffer()
    assert len(sb) == 32
    sb.wipe()
    assert buf == bytearray(32)
    assert sb.wiped and len(sb) == 0
    with pytest.raises(ValueError):
        sb.buffer()
    sb.wipe()  # a second wipe does nothing


def test_secret_bytes_hides_content():
    sb = SecretBytes.from_bytes(b"AAAA")
    assert "AAAA" not in repr(sb) and "41" not in repr(sb)
    assert "AAAA" not in str(sb)
    with pytest.raises(TypeError):
        pickle.dumps(sb)


def test_secret_bytes_context_manager():
    with SecretBytes(16) as sb:
        buf = sb.buffer()
        buf[:] = b"x" * 16
    assert buf == bytearray(16)


@pytest.mark.skipif(os.name != "nt", reason="mlock may be limited by RLIMIT_MEMLOCK")
def test_secret_bytes_locked_in_ram_on_windows():
    assert SecretBytes(32).locked_in_ram


# ---------------------------------------------------------------- crypto

def test_derive_key_wipes_the_encoded_password(monkeypatch):
    seen = []
    real = crypto.wipe
    monkeypatch.setattr(crypto, "wipe", lambda o: (seen.append((bytes(bytearray(o)), o)), real(o)))
    key = crypto.derive_key(MASTER, crypto.new_salt(), crypto.DEFAULT_KDF_PARAMS)
    assert isinstance(key, SecretBytes) and len(key) == 32
    assert [before for before, _ in seen] == [MASTER.encode()]
    assert all(zeroed(obj) for _, obj in seen)


def _capture_wipe_all(monkeypatch):
    seen = []
    real = crypto.wipe_all

    def spy(*objs):
        seen.extend(o for o in objs if o is not None)
        real(*objs)

    monkeypatch.setattr(crypto, "wipe_all", spy)
    return seen


def test_encrypt_and_decrypt_wipe_the_plaintext(monkeypatch):
    payload = {"entries": {"github": {"password": "Secret-pw-1"}}}
    salt = crypto.new_salt()
    key = crypto.derive_key(MASTER, salt, crypto.DEFAULT_KDF_PARAMS)

    seen = _capture_wipe_all(monkeypatch)
    doc = crypto.encrypt_vault(key, salt, crypto.DEFAULT_KDF_PARAMS, payload)
    assert {type(o) for o in seen} == {str, bytes}  # the JSON text and its bytes
    assert all(zeroed(o) for o in seen)

    seen.clear()
    key2, _, _, out = crypto.decrypt_vault(MASTER, doc)
    assert out == payload
    assert {type(o) for o in seen} == {str, bytes}
    assert all(zeroed(o) for o in seen)
    key.wipe()
    key2.wipe()


def test_decrypt_wipes_the_key_on_failure(monkeypatch):
    salt = crypto.new_salt()
    key = crypto.derive_key(MASTER, salt, crypto.DEFAULT_KDF_PARAMS)
    doc = crypto.encrypt_vault(key, salt, crypto.DEFAULT_KDF_PARAMS, {"entries": {}})
    made = []
    real = crypto.derive_key
    monkeypatch.setattr(crypto, "derive_key", lambda *a: made.append(real(*a)) or made[-1])
    with pytest.raises(crypto.VaultError):
        crypto.decrypt_vault("wrong password", doc)
    assert made[0].wiped


# ---------------------------------------------------------------- vault

@pytest.fixture
def path(tmp_path):
    return storage.resolve_path(str(tmp_path / "vault.json"))


def test_lock_wipes_every_stored_string(path):
    with Vault.create(path, MASTER) as v:
        v.add("github", "javid", "Secret-pw-1", "my notes")
        v.save()
    v = Vault.unlock(path, MASTER)
    name = next(iter(v._entries))
    entry = v._entries["github"]
    refs = [name, entry["username"], entry["password"], entry["notes"]]
    key = v._key
    v.lock()
    assert all(zeroed(r) for r in refs)
    assert key.wiped
    assert v._entries == {}


def test_vault_keeps_its_own_copies(path):
    # Wiping on lock must never change a string the caller still has.
    pw = "".join(["Secret", "-pw-2"])
    user = "".join(["ja", "vid"])
    with Vault.create(path, MASTER) as v:
        v.add("site", user, pw, "")
        assert v.get("site")["password"] is not pw
    assert pw == "Secret-pw-2" and user == "javid"


def test_update_and_delete_wipe_old_values(path):
    with Vault.create(path, MASTER) as v:
        v.add("site", "user", "old-password", "notes")
        old = v._entries["site"]["password"]
        v.update("site", password="new-password")
        assert zeroed(old)
        entry = v._entries["site"]
        refs = [entry["username"], entry["password"]]
        v.delete("site")
        assert all(zeroed(r) for r in refs)


def test_cli_wipes_every_typed_secret(vault, term):
    term.typed.clear()
    assert add(vault, term, pw="Secret-pw-9") == 0
    term.secrets = [MASTER, "another long password", "another long password"]
    assert cli.main(["--vault", vault, "change-master"]) == 0
    assert len(term.typed) == 6
    assert all(zeroed(s) for s in term.typed)


def test_cli_wipes_master_after_wrong_password(vault, term):
    term.typed.clear()
    term.secrets = ["wrong password!!"]
    assert cli.main(["--vault", vault, "list"]) == 1
    assert zeroed(term.typed[0])


def test_generated_password_wiped_after_copy(term, tmp_path, monkeypatch):
    copied = []
    monkeypatch.setattr(cli.clipboard, "_copy", copied.append)
    assert cli.main(["--vault", str(tmp_path / "v.json"), "generate"]) == 0
    assert len(copied) == 1 and zeroed(copied[0])
