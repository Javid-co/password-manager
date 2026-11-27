"""Structured logging (L1-L3): key events are logged, secrets never are."""

import json
import os

import pytest
from conftest import MASTER, add

from pwmanager import access, audit, cli

NEW_MASTER = "another long master password"
ENTRY_PW = "Entry-Secret-pw-77"
USERNAME = "javid.secret.user"
NOTES = "my secret notes 1234"
NAME = "mybank"


def log_lines(vault):
    path = audit.log_path(vault)
    with open(path, encoding="ascii") as f:
        return [json.loads(line) for line in f]


def run_everything(vault, term):
    """Use every command once, including some failures."""
    add(vault, term, name=NAME, user=USERNAME, pw=ENTRY_PW, notes=NOTES)
    term.secrets = [MASTER]
    cli.main(["--vault", vault, "get", "--copy", NAME])
    term.secrets = [MASTER]
    cli.main(["--vault", vault, "list"])
    term.secrets = [MASTER, "Updated-pw-88", "Updated-pw-88"]
    term.lines = ["", "y", "new " + NOTES]
    cli.main(["--vault", vault, "update", NAME])
    term.secrets = ["wrong " + MASTER]
    cli.main(["--vault", vault, "list"])
    term.secrets = [MASTER]
    term.lines = ["bad\x1b[2J"]
    cli.main(["--vault", vault, "add", "other"])
    term.secrets = [MASTER, NEW_MASTER, NEW_MASTER]
    cli.main(["--vault", vault, "change-master"])
    term.secrets = [NEW_MASTER]
    term.lines = ["y"]
    cli.main(["--vault", vault, "delete", NAME])
    cli.main(["--vault", vault, "generate"])


def test_every_line_is_a_json_event(vault, term):
    run_everything(vault, term)
    lines = log_lines(vault)
    assert len(lines) > 10
    for line in lines:
        assert {"ts", "level", "event", "outcome", "command", "user", "pid"} <= set(line)
        assert line["event"] in audit.EVENTS
        assert line["outcome"] in audit.OUTCOMES
        assert line["user"] == access.current_user()
        assert line["ts"].endswith("Z")


def test_key_events_are_logged(vault, term):
    run_everything(vault, term)
    events = [(line["event"], line["outcome"]) for line in log_lines(vault)]
    for expected in [
        ("vault.init", "ok"), ("vault.unlock", "ok"), ("vault.unlock", "fail"),
        ("entry.add", "ok"), ("entry.read", "ok"), ("entry.copy", "ok"), ("entry.list", "ok"),
        ("entry.update", "ok"), ("entry.delete", "ok"), ("vault.save", "ok"),
        ("master.change", "ok"), ("password.generate", "ok"), ("input.rejected", "fail"),
    ]:
        assert expected in events


def test_no_secret_is_ever_written_to_the_log(vault, term):
    run_everything(vault, term)
    folder = os.path.dirname(vault)
    text = open(audit.log_path(vault), encoding="ascii").read()
    for secret in (MASTER, NEW_MASTER, ENTRY_PW, "Updated-pw-88", USERNAME, NOTES, NAME,
                   "wrong " + MASTER):
        assert secret not in text
    # And no other file in the folder has them in plain text either.
    for name in os.listdir(folder):
        data = open(os.path.join(folder, name), "rb").read()
        for secret in (MASTER, NEW_MASTER, ENTRY_PW, USERNAME, NOTES, NAME):
            assert secret.encode() not in data, name


def test_wrong_password_is_a_warning(vault, term):
    term.secrets = ["not the password!"]
    cli.main(["--vault", vault, "list"])
    last = [line for line in log_lines(vault) if line["event"] == "vault.unlock"][-1]
    assert last["level"] == "WARNING"
    assert last["outcome"] == "fail"
    assert last["reason"] == "bad_password_or_changed_file"


def test_unexpected_error_logs_only_the_type(vault, term, capsys, monkeypatch):
    def boom(*a):
        raise RuntimeError("secret detail " + MASTER)

    monkeypatch.setattr(cli.Vault, "unlock", boom)
    term.secrets = [MASTER]
    assert cli.main(["--vault", vault, "list"]) == 1
    err = capsys.readouterr().err
    assert err == "error: unexpected error\n"
    last = log_lines(vault)[-1]
    assert last["event"] == "error" and last["reason"] == "RuntimeError"
    assert "secret detail" not in open(audit.log_path(vault)).read()


def test_library_error_message_is_not_shown(vault, term, capsys, monkeypatch):
    def boom(*a):
        raise ValueError("internal detail from a library")

    monkeypatch.setattr(cli.Vault, "unlock", boom)
    term.secrets = [MASTER]
    cli.main(["--vault", vault, "list"])
    assert "internal detail" not in capsys.readouterr().err


def test_unknown_event_or_field_is_a_bug():
    with pytest.raises(ValueError):
        audit.event("password.was", "ok")
    with pytest.raises(ValueError):
        audit.event("entry.add", "ok", name="github")
    with pytest.raises(ValueError):
        audit.event("entry.add", "maybe")


def test_field_values_must_match_their_pattern(tmp_path):
    vault = str(tmp_path / "vault.json")
    audit.setup(vault, "list")
    audit.event("error", "fail", reason="has spaces " + MASTER)
    audit.event("access.fixed", file="../../etc/passwd")
    audit.event("entry.list", count="12")
    audit.shutdown()
    lines = log_lines(vault)
    assert lines[0]["reason"] == "invalid"
    assert lines[1]["file"] == "invalid"
    assert lines[2]["count"] == "invalid"


def test_log_injection_is_not_possible(tmp_path):
    vault = str(tmp_path / "vault.json")
    audit.setup(vault, "list")
    audit.event("error", "fail", reason='x"}\n{"event":"vault.unlock","outcome":"ok')
    audit.shutdown()
    lines = log_lines(vault)
    assert len(lines) == 1 and lines[0]["reason"] == "invalid"


def test_logging_problems_never_break_the_program(vault, term, capsys):
    # A folder where the log file should be, so the log can't be opened.
    os.remove(audit.log_path(vault))
    os.mkdir(audit.log_path(vault))
    capsys.readouterr()
    assert add(vault, term) == 0
    assert capsys.readouterr().err == ""


def test_nothing_is_printed_without_setup(capsys):
    audit.event("error", "fail", reason="Test")
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


def test_log_rotation(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "MAX_LOG_SIZE", 300)
    vault = str(tmp_path / "vault.json")
    audit.setup(vault, "list")
    for _ in range(10):
        audit.event("entry.list", count=1)
    audit.shutdown()
    assert os.path.exists(audit.log_path(vault) + ".1")
    assert os.path.getsize(audit.log_path(vault)) < 600
