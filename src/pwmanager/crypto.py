"""Encryption module: Argon2id key derivation and AES-256-GCM.

This is the only module that uses the crypto libraries. See docs/design.md,
sections "Crypto scheme" and "Vault format".
"""

import base64
import binascii
import json
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = "pwm-vault"
VERSION = 1
KDF = "argon2id"
CIPHER = "aes-256-gcm"

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

# The settings used for new vaults. memory_cost is in KiB (65536 = 64 MiB).
DEFAULT_KDF_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}

# V3: a vault with settings below these is refused, so nobody can make
# guessing cheaper by editing the header. The upper limits stop a changed
# header from making the program use huge amounts of memory or time.
MIN_KDF_PARAMS = dict(DEFAULT_KDF_PARAMS)
MAX_KDF_PARAMS = {"time_cost": 20, "memory_cost": 1048576, "parallelism": 16}


class VaultError(Exception):
    """Raised for any problem opening a vault.

    The message is the same for a wrong password and a changed file, so the
    error does not tell an attacker which one it was.
    """

    def __init__(self, message="could not unlock vault"):
        super().__init__(message)


def _b64encode(data):
    return base64.b64encode(data).decode("ascii")


def _b64decode(text, expected_len=None):
    if not isinstance(text, str):
        raise VaultError()
    try:
        data = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise VaultError() from None
    if expected_len is not None and len(data) != expected_len:
        raise VaultError()
    return data


def header_bytes(header):
    """Turn the header into the exact bytes used as associated data."""
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def check_kdf_params(params):
    """Make sure the KDF settings are complete and inside the allowed range."""
    if not isinstance(params, dict) or set(params) != set(DEFAULT_KDF_PARAMS):
        raise VaultError()
    for name, value in params.items():
        # bool is a subclass of int in Python, so it is checked separately
        if not isinstance(value, int) or isinstance(value, bool):
            raise VaultError()
        if not MIN_KDF_PARAMS[name] <= value <= MAX_KDF_PARAMS[name]:
            raise VaultError()


def derive_key(master_password, salt, params):
    """Derive the 32-byte AES key from the master password with Argon2id."""
    check_kdf_params(params)
    if len(salt) != SALT_LEN:
        raise VaultError()
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def new_salt():
    return os.urandom(SALT_LEN)


def encrypt_vault(key, salt, params, payload):
    """Encrypt the payload (a dict) and return the full vault document.

    V4: a new random nonce is made on every call, so the same nonce is
    never used twice with one key.
    """
    nonce = os.urandom(NONCE_LEN)
    header = {
        "format": FORMAT,
        "version": VERSION,
        "kdf": KDF,
        "kdf_params": dict(params),
        "salt": _b64encode(salt),
        "cipher": CIPHER,
        "nonce": _b64encode(nonce),
    }
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header_bytes(header))
    return {"header": header, "ciphertext": _b64encode(ciphertext)}


def read_header(vault):
    """Check the header of a vault document and return (salt, params, nonce).

    Nothing here is trusted yet. The GCM tag check in decrypt_vault is what
    proves the header was not changed.
    """
    if not isinstance(vault, dict) or set(vault) != {"header", "ciphertext"}:
        raise VaultError()
    header = vault["header"]
    expected = {"format", "version", "kdf", "kdf_params", "salt", "cipher", "nonce"}
    if not isinstance(header, dict) or set(header) != expected:
        raise VaultError()
    if (
        header["format"] != FORMAT
        or header["version"] != VERSION
        or header["kdf"] != KDF
        or header["cipher"] != CIPHER
    ):
        raise VaultError()
    check_kdf_params(header["kdf_params"])
    salt = _b64decode(header["salt"], SALT_LEN)
    nonce = _b64decode(header["nonce"], NONCE_LEN)
    return salt, header["kdf_params"], nonce


def decrypt_vault(master_password, vault):
    """Open a vault document with the master password.

    Returns (key, salt, params, payload). The key is returned so the vault
    can be saved again without running Argon2id a second time.
    Raises VaultError if the password is wrong or the file was changed.
    """
    salt, params, nonce = read_header(vault)
    ciphertext = _b64decode(vault["ciphertext"])
    key = derive_key(master_password, salt, params)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header_bytes(vault["header"]))
    except InvalidTag:
        raise VaultError() from None
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise VaultError() from None
    if not isinstance(payload, dict):
        raise VaultError()
    return key, salt, params, payload
