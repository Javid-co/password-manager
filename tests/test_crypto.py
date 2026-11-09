import base64
import copy

import pytest

from pwmanager import crypto
from pwmanager.crypto import VaultError

PASSWORD = "correct horse battery staple"
PAYLOAD = {"entries": {"github": {"username": "javid", "password": "s3cret!"}}}


@pytest.fixture(scope="module")
def vault():
    salt = crypto.new_salt()
    key = crypto.derive_key(PASSWORD, salt, crypto.DEFAULT_KDF_PARAMS)
    return crypto.encrypt_vault(key, salt, crypto.DEFAULT_KDF_PARAMS, PAYLOAD)


def test_round_trip(vault):
    _key, _salt, _params, payload = crypto.decrypt_vault(PASSWORD, vault)
    assert payload == PAYLOAD


def test_password_not_in_file(vault):
    assert "s3cret!" not in str(vault)
    assert "github" not in str(vault)


def test_wrong_password(vault):
    with pytest.raises(VaultError, match="could not unlock vault"):
        crypto.decrypt_vault("wrong password", vault)


def test_new_nonce_every_save():
    salt = crypto.new_salt()
    key = crypto.derive_key(PASSWORD, salt, crypto.DEFAULT_KDF_PARAMS)
    a = crypto.encrypt_vault(key, salt, crypto.DEFAULT_KDF_PARAMS, PAYLOAD)
    b = crypto.encrypt_vault(key, salt, crypto.DEFAULT_KDF_PARAMS, PAYLOAD)
    assert a["header"]["nonce"] != b["header"]["nonce"]
    assert a["ciphertext"] != b["ciphertext"]


def test_changed_ciphertext(vault):
    bad = copy.deepcopy(vault)
    raw = bytearray(base64.b64decode(bad["ciphertext"]))
    raw[0] ^= 1
    bad["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(VaultError):
        crypto.decrypt_vault(PASSWORD, bad)


def test_changed_header_salt(vault):
    bad = copy.deepcopy(vault)
    bad["header"]["salt"] = base64.b64encode(b"\x00" * 16).decode()
    with pytest.raises(VaultError):
        crypto.decrypt_vault(PASSWORD, bad)


def test_raised_kdf_setting_fails_tag_check(vault):
    # Still inside the allowed range, so only the GCM tag catches it.
    bad = copy.deepcopy(vault)
    bad["header"]["kdf_params"]["time_cost"] = 4
    with pytest.raises(VaultError):
        crypto.decrypt_vault(PASSWORD, bad)


@pytest.mark.parametrize(
    "name, value",
    [("time_cost", 1), ("memory_cost", 8), ("parallelism", 1)],
)
def test_weak_kdf_settings_refused(vault, name, value):
    bad = copy.deepcopy(vault)
    bad["header"]["kdf_params"][name] = value
    with pytest.raises(VaultError):
        crypto.read_header(bad)


def test_huge_kdf_settings_refused(vault):
    bad = copy.deepcopy(vault)
    bad["header"]["kdf_params"]["memory_cost"] = 2**31
    with pytest.raises(VaultError):
        crypto.read_header(bad)


@pytest.mark.parametrize(
    "field, value",
    [
        ("format", "other"),
        ("version", 2),
        ("kdf", "pbkdf2"),
        ("cipher", "aes-128-cbc"),
        ("nonce", "not base64!"),
        ("salt", base64.b64encode(b"short").decode()),
    ],
)
def test_bad_header_fields(vault, field, value):
    bad = copy.deepcopy(vault)
    bad["header"][field] = value
    with pytest.raises(VaultError):
        crypto.read_header(bad)


def test_extra_or_missing_keys(vault):
    extra = copy.deepcopy(vault)
    extra["header"]["extra"] = 1
    missing = copy.deepcopy(vault)
    del missing["header"]["nonce"]
    for bad in (extra, missing, {"header": vault["header"]}, None, []):
        with pytest.raises(VaultError):
            crypto.read_header(bad)
