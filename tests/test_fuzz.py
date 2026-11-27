"""Simple fuzzing of everything that reads the vault file.

A valid vault file is changed at random many times (flipped bytes, cut
pieces, inserted junk, deep nesting). Opening it must either work or fail
with one of our own errors. Any other exception (KeyError, TypeError,
RecursionError, ...) would be a bug that could crash the program or print a
traceback. The random seed is fixed, so a failure can be repeated.

Argon2id with 64 MiB is replaced by a fast fake here. Only the parsing and
the checks are being tested, not the key derivation.
"""

import base64
import hashlib
import json
import random

import pytest

from pwmanager import crypto, storage
from pwmanager.errors import PwmError
from pwmanager.secmem import SecretBytes
from pwmanager.vault import Vault

MASTER = "a long master password"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    def fake(password, salt, params):
        crypto.check_kdf_params(params)
        if len(salt) != crypto.SALT_LEN:
            raise crypto.VaultError()
        return SecretBytes.from_bytes(hashlib.sha256(password.encode() + salt).digest())

    monkeypatch.setattr(crypto, "derive_key", fake)


@pytest.fixture
def path(tmp_path):
    p = storage.resolve_path(str(tmp_path / "vault.json"))
    with Vault.create(p, MASTER) as v:
        v.add("github", "javid", "Secret-pw-1", "notes")
        v.add("bank", "me", "pin", "")
        v.save()
    return p


def try_open(path):
    try:
        Vault.unlock(path, MASTER).lock()
    except PwmError:
        pass


def mutate(data, rng):
    data = bytearray(data)
    kind = rng.randrange(5)
    if kind == 0:
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
    elif kind == 1:
        start = rng.randrange(len(data))
        del data[start:start + rng.randint(1, 50)]
    elif kind == 2:
        pos = rng.randrange(len(data))
        junk = bytes(rng.choice(b'{}[]",:0123456789abcdef\\ \x00\xff') for _ in range(20))
        data[pos:pos] = junk
    elif kind == 3:
        data = data[:rng.randrange(len(data))]
    else:
        data = data + data
    return bytes(data)


def test_random_changes_to_the_file(path):
    original = open(path, "rb").read()
    rng = random.Random(22)
    for _ in range(400):
        with open(path, "wb") as f:
            f.write(mutate(original, rng))
        try_open(path)


def test_random_changes_to_the_header(path):
    original = json.loads(open(path, "rb").read())
    rng = random.Random(7)
    values = [None, True, 0, -1, 2**64, 1.5, "", "x" * 100, [], {}, [1], {"a": 1},
              "AAAA", base64.b64encode(bytes(16)).decode()]
    for _ in range(300):
        doc = json.loads(json.dumps(original))
        target = doc["header"]
        if rng.random() < 0.3:
            target = doc["header"]["kdf_params"]
        key = rng.choice(list(target) + ["new"])
        if rng.random() < 0.2:
            target.pop(key, None)
        else:
            target[key] = rng.choice(values)
        if rng.random() < 0.1:
            doc = rng.choice(values)
        storage.write_vault(path, doc)
        try_open(path)


def test_deep_nesting(path):
    with open(path, "w") as f:
        f.write("[" * 200000 + "]" * 200000)
    with pytest.raises(PwmError):
        Vault.unlock(path, MASTER)


def test_correctly_encrypted_but_wrong_contents(path):
    """Even with the right key, a payload with the wrong shape is refused."""
    doc = json.loads(open(path, "rb").read())
    salt = base64.b64decode(doc["header"]["salt"])
    params = doc["header"]["kdf_params"]
    rng = random.Random(3)
    good = {"username": "u", "password": "p", "notes": "",
            "created": "2026-11-27T10:00:00Z", "modified": "2026-11-27T10:00:00Z"}
    values = [None, 1, "x", [], {}, "a\x1b", "x" * 5000, dict(good)]
    for _ in range(200):
        entry = dict(good)
        entry[rng.choice(list(good) + ["extra"])] = rng.choice(values)
        name = rng.choice(["ok", "../x", "", "a b", 5])
        payload = rng.choice([{"entries": {name: entry}}, {"entries": entry}, [entry],
                              {"entries": {"ok": entry}, "x": 1}])
        key = crypto.derive_key(MASTER, salt, params)
        try:
            storage.write_vault(path, crypto.encrypt_vault(key, salt, params, payload))
        except (TypeError, ValueError):
            continue  # cannot even be turned into JSON
        finally:
            key.wipe()
        try_open(path)
