"""Input validation edge cases (I1) for every field."""

import pytest

from pwmanager import storage, validate
from pwmanager.validate import ValidationError
from pwmanager.vault import Vault

MASTER = "a long master password"

GOOD_RECORD = {"username": "javid", "password": "pw", "notes": "",
               "created": "2026-11-27T10:00:00Z", "modified": "2026-11-27T10:00:00Z"}


# ---------------------------------------------------------------- entry names

@pytest.mark.parametrize("value", ["a", "github", "my.site@work-1", "A_B", "x" * 64])
def test_good_names(value):
    assert validate.entry_name(value) == value


@pytest.mark.parametrize("value", [
    "", "x" * 65, "a b", "../x", "a/b", "a\\b", "é", "a;b", "$(id)", "`id`", "a|b",
    "a\x00", "a\n", "‮gnp", "a​b", None, 5, b"bytes",
])
def test_bad_names(value):
    with pytest.raises(ValidationError):
        validate.entry_name(value)


# ---------------------------------------------------------------- --length

@pytest.mark.parametrize("value, expected", [("8", 8), ("128", 128), ("020", 20), (20, 20)])
def test_good_lengths(value, expected):
    assert validate.gen_length(value) == expected


@pytest.mark.parametrize("value", [
    "7", "129", "", "abc", " 20", "20 ", "2_0", "+20", "-5", "1e3", "0x10", "20.0",
    "٣٣",  # Arabic-Indic digits, int() would accept them
    7, 129, True, 20.0, None,
])
def test_bad_lengths(value):
    with pytest.raises(ValidationError):
        validate.gen_length(value)


# ---------------------------------------------------------------- text fields

@pytest.mark.parametrize("value", ["", "javid", "Jürgen Müller", "名前", "emoji 😀", "a b c",
                                   "x" * 256])
def test_good_usernames(value):
    assert validate.username(value) == value


@pytest.mark.parametrize("value", [
    "x" * 257,
    "red\x1b[31m",      # terminal escape sequence
    "tab\there", "line\nbreak", "cr\r", "nul\x00", "del\x7f", "c1\x85",
    "admin‮",      # right-to-left override
    "ad​min",      # zero-width space
    "bom﻿",        # zero-width no-break space
    "sur\ud800",        # lone surrogate
    "ls ", "ps ",
    "pua",        # private use
    "x" * 2000,         # far too long, refused before normalising
    None, 1,
])
def test_bad_usernames(value):
    with pytest.raises(ValidationError):
        validate.username(value)


def test_text_is_normalised_to_nfc():
    assert validate.username("é") == "é"
    assert validate.notes("Café") == "Café"


def test_length_counted_after_normalising():
    # 256 "é" written as e + combining accent = 512 code points before NFC.
    assert len(validate.username("é" * 256)) == 256
    with pytest.raises(ValidationError):
        validate.username("é" * 257)


def test_notes_limit():
    validate.notes("n" * 1024)
    with pytest.raises(ValidationError):
        validate.notes("n" * 1025)


# ---------------------------------------------------------------- passwords

def test_password_kept_exactly():
    # Not normalised: the website expects the exact characters.
    assert validate.password("é") == "é"
    assert validate.password(" spaces are fine ") == " spaces are fine "
    assert validate.password("p" * 1024)


@pytest.mark.parametrize("value", ["", "p" * 1025, "a\x00b", "a\nb", "a​b", "\ud800x", None])
def test_bad_passwords(value):
    with pytest.raises(ValidationError):
        validate.password(value)


@pytest.mark.parametrize("value, ok", [
    ("x" * 11, False), ("x" * 12, True), ("x" * 1024, True), ("x" * 1025, False),
    ("twelve chars\n", False), ("twelve‮chars", False),
])
def test_master_password(value, ok):
    if ok:
        assert validate.master_password(value) == value
    else:
        with pytest.raises(ValidationError):
            validate.master_password(value)


def test_master_attempt_only_checks_upper_limit():
    assert validate.master_password_attempt("short") == "short"
    with pytest.raises(ValidationError):
        validate.master_password_attempt("x" * 1025)


# ---------------------------------------------------------------- answers

@pytest.mark.parametrize("value, expected", [("y", "y"), (" YES ", "yes"), ("", "")])
def test_answers(value, expected):
    assert validate.answer(value) == expected


@pytest.mark.parametrize("value", ["y" * 17, "y\x1b", None])
def test_bad_answers(value):
    with pytest.raises(ValidationError):
        validate.answer(value)


# ---------------------------------------------------------------- stored records

def test_good_payload():
    validate.payload({"entries": {"github": dict(GOOD_RECORD)}})
    validate.payload({"entries": {}})


@pytest.mark.parametrize("change", [
    {"password": 5},
    {"username": ["list"]},
    {"username": "bad\x1b"},
    {"notes": "x" * 1025},
    {"created": "yesterday"},
    {"modified": "2026-11-27 10:00:00"},
    {"extra": "field"},
])
def test_bad_records(change):
    record = dict(GOOD_RECORD, **change)
    with pytest.raises(ValidationError):
        validate.payload({"entries": {"github": record}})


def test_missing_field_and_bad_name():
    record = dict(GOOD_RECORD)
    del record["notes"]
    for bad in ({"entries": {"github": record}},
                {"entries": {"../x": dict(GOOD_RECORD)}},
                {"entries": {"github": "not a dict"}},
                {"entries": []}, {"entries": {}, "more": 1}, [], None):
        with pytest.raises(ValidationError):
            validate.payload(bad)


def test_too_many_entries(monkeypatch):
    monkeypatch.setattr(validate, "MAX_ENTRIES", 2)
    entries = {f"e{i}": dict(GOOD_RECORD) for i in range(3)}
    with pytest.raises(ValidationError):
        validate.payload({"entries": entries})


# ---------------------------------------------------------------- the vault checks too

def test_vault_validates_without_the_cli(tmp_path):
    path = storage.resolve_path(str(tmp_path / "vault.json"))
    with Vault.create(path, MASTER) as v:
        with pytest.raises(ValidationError):
            v.add("ok", "user\x1b[2J", "pw", "")
        with pytest.raises(ValidationError):
            v.add("../etc", "user", "pw", "")
        with pytest.raises(ValidationError):
            v.add("ok", "user", "", "")
        v.add("ok", "user", "pw", "")
        with pytest.raises(ValidationError):
            v.update("ok", notes="a‮b")
        with pytest.raises(ValidationError):
            v.update("ok", created="2000-01-01T00:00:00Z")
        with pytest.raises(ValidationError):
            v.change_master("short")


# ---------------------------------------------------------------- vault path

@pytest.mark.parametrize("bad", ["v\x1b[2J.json", "v‮nosj.json", "v\nx.json"])
def test_bad_vault_path_characters(bad):
    with pytest.raises(storage.StorageError):
        storage.resolve_path(bad)
