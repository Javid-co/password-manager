"""Input validation and sanitization for every field (I1).

All checks live here so the CLI and the vault use the same rules. The vault
calls them again on every record operation, so no caller can skip them, and
also on the records it reads after decrypting a vault.

The rules are allow-lists where possible (Week 4). For free text fields
(username, notes, passwords) an allow-list of characters would be too strict,
so instead these Unicode categories are refused:

  Cc  control characters (NUL, ESC, newline, tab ...). ESC sequences could
      change the terminal when the field is printed.
  Cf  invisible format characters, like U+202E (right-to-left override) and
      U+200B (zero-width space). They can make text look different from
      what it is, for example a fake username.
  Cs  lone surrogates. They are not real characters and break UTF-8.
  Co  private use characters.
  Cn  unassigned code points.
  Zl, Zp  line and paragraph separators (they act like a newline).
"""

import re
import unicodedata

from .errors import PwmError

NAME_RE = re.compile(r"[A-Za-z0-9._@-]{1,64}")
LENGTH_RE = re.compile(r"[0-9]{1,3}")
TIMESTAMP_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

MIN_GEN_LEN, MAX_GEN_LEN, DEFAULT_GEN_LEN = 8, 128, 20
MIN_MASTER_LEN, MAX_MASTER_LEN = 12, 1024
# bandit B105 thinks "password": 1024 is a hard-coded password. It is a length limit.
MAX_FIELD_LEN = {"username": 256, "password": 1024, "notes": 1024}  # nosec B105
MAX_ANSWER_LEN = 16
MAX_ENTRIES = 10000

ENTRY_FIELDS = ("username", "password", "notes")
STORED_FIELDS = set(ENTRY_FIELDS) | {"created", "modified"}

_BAD_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


class ValidationError(PwmError):
    pass


def _bad_char(value):
    return any(unicodedata.category(c) in _BAD_CATEGORIES for c in value)


def entry_name(value):
    if not isinstance(value, str) or not NAME_RE.fullmatch(value):
        raise ValidationError("entry name must be 1-64 characters: letters, digits, . _ @ -")
    return value


def gen_length(value):
    """--length. int() alone would also accept " 20", "2_0" and "+20"."""
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and LENGTH_RE.fullmatch(value):
        number = int(value)
    else:
        number = None
    if number is None or not MIN_GEN_LEN <= number <= MAX_GEN_LEN:
        raise ValidationError(
            f"length must be a whole number from {MIN_GEN_LEN} to {MAX_GEN_LEN}")
    return number


def text_field(label, value, max_len):
    """Username and notes. Normalised to NFC so the same text always has the
    same code points (an "é" typed two different ways becomes one form)."""
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be text")
    if len(value) > max_len * 4:
        # Checked before normalising, so a huge input is not processed.
        raise ValidationError(f"{label} is too long (max {max_len} characters)")
    value = unicodedata.normalize("NFC", value)
    if len(value) > max_len:
        raise ValidationError(f"{label} is too long (max {max_len} characters)")
    if _bad_char(value):
        raise ValidationError(f"{label} must not contain control or invisible characters")
    return value


def secret_field(label, value, max_len, min_len=0):
    """Passwords. Not normalised: a stored password must stay exactly as the
    website expects it."""
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be text")
    if len(value) > max_len:
        raise ValidationError(f"{label} is too long (max {max_len} characters)")
    if len(value) < min_len:
        raise ValidationError(f"{label} must be at least {min_len} characters")
    if _bad_char(value):
        raise ValidationError(f"{label} must not contain control or invisible characters")
    return value


def username(value):
    return text_field("username", value, MAX_FIELD_LEN["username"])


def notes(value):
    return text_field("notes", value, MAX_FIELD_LEN["notes"])


def password(value, label="password"):
    value = secret_field(label, value, MAX_FIELD_LEN["password"])
    if not value:
        raise ValidationError(f"{label} must not be empty")
    return value


def master_password(value, label="master password"):
    """M1: 12 to 1024 characters."""
    return secret_field(label, value, MAX_MASTER_LEN, MIN_MASTER_LEN)


def master_password_attempt(value):
    """The password typed to unlock. Only the upper limit is checked here,
    a short one simply fails to decrypt."""
    return secret_field("master password", value, MAX_MASTER_LEN)


def answer(value):
    """A y/N answer."""
    if not isinstance(value, str) or len(value) > MAX_ANSWER_LEN or _bad_char(value):
        raise ValidationError("invalid answer")
    return value.strip().lower()


def field(name, value):
    """Validate one entry field by its name."""
    if name == "username":
        return username(value)
    if name == "password":
        return password(value)
    if name == "notes":
        return notes(value)
    raise ValidationError("unknown field")


def stored_entry(name, entry):
    """Check one record read from a decrypted vault.

    The GCM tag already proves we wrote it, but the record still goes
    through the same rules, in case an older version or a bug stored
    something that is not allowed.
    """
    entry_name(name)
    if not isinstance(entry, dict) or set(entry) != STORED_FIELDS:
        raise ValidationError("invalid record")
    for key in ("created", "modified"):
        if not isinstance(entry[key], str) or not TIMESTAMP_RE.fullmatch(entry[key]):
            raise ValidationError("invalid record")
    username(entry["username"])
    notes(entry["notes"])
    if not isinstance(entry["password"], str):
        raise ValidationError("invalid record")
    secret_field("password", entry["password"], MAX_FIELD_LEN["password"])


def payload(data):
    """Check the whole decrypted payload: {"entries": {name: record}}."""
    if not isinstance(data, dict) or set(data) != {"entries"}:
        raise ValidationError("invalid vault contents")
    entries = data["entries"]
    if not isinstance(entries, dict) or len(entries) > MAX_ENTRIES:
        raise ValidationError("invalid vault contents")
    for name, entry in entries.items():
        stored_entry(name, entry)
