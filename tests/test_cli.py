"""CLI tests. getpass, input and the clipboard are replaced with fakes."""

import pytest

from pwmanager import cli, clipboard

MASTER = "a long master password"


class FakeTerminal:
    def __init__(self, monkeypatch):
        self.secrets = []
        self.lines = []
        self.clipboard = None
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": self.secrets.pop(0))
        monkeypatch.setattr("builtins.input", lambda prompt="": self.lines.pop(0))
        monkeypatch.setattr(clipboard, "_copy", self._copy)
        monkeypatch.setattr(clipboard, "_paste", lambda: self.clipboard or "")
        monkeypatch.setattr(clipboard, "_clear", self._clear)
        monkeypatch.setattr(cli, "CLIPBOARD_SECONDS", 0)

    def _copy(self, text):
        self.clipboard = text

    def _clear(self):
        self.clipboard = None


@pytest.fixture
def term(monkeypatch):
    return FakeTerminal(monkeypatch)


@pytest.fixture
def vault(tmp_path, term):
    path = str(tmp_path / "vault.json")
    term.secrets = [MASTER, MASTER]
    assert cli.main(["--vault", path, "init"]) == 0
    return path


def add(path, term, name="github", user="javid", pw="Secret-pw-1", notes=""):
    term.secrets = [MASTER, pw, pw]
    term.lines = [user, notes]
    return cli.main(["--vault", path, "add", name])


def test_add_and_get_never_prints_password(vault, term, capsys):
    assert add(vault, term) == 0
    term.secrets = [MASTER]
    assert cli.main(["--vault", vault, "get", "github"]) == 0
    out = capsys.readouterr().out
    assert "javid" in out
    assert "Secret-pw-1" not in out


def test_get_copy_puts_password_on_clipboard_then_clears(vault, term, capsys, monkeypatch):
    add(vault, term)
    seen = []
    monkeypatch.setattr(cli.time, "sleep", lambda s: seen.append(term.clipboard))
    term.secrets = [MASTER]
    assert cli.main(["--vault", vault, "get", "--copy", "github"]) == 0
    assert seen == ["Secret-pw-1"]
    assert term.clipboard is None
    assert "Secret-pw-1" not in capsys.readouterr().out


def test_clipboard_left_alone_if_user_copied_something_else(vault, term, monkeypatch):
    add(vault, term)

    def user_copies(_):
        term.clipboard = "something else"

    monkeypatch.setattr(cli.time, "sleep", user_copies)
    term.secrets = [MASTER]
    cli.main(["--vault", vault, "get", "--copy", "github"])
    assert term.clipboard == "something else"


def test_wrong_master_password(vault, term, capsys):
    term.secrets = ["wrong password!!"]
    assert cli.main(["--vault", vault, "list"]) == 1
    assert "could not unlock vault" in capsys.readouterr().err


def test_list(vault, term, capsys):
    add(vault, term, "github")
    add(vault, term, "bank", user="me", pw="x")
    capsys.readouterr()
    term.secrets = [MASTER]
    assert cli.main(["--vault", vault, "list"]) == 0
    out = capsys.readouterr().out
    assert out.index("bank") < out.index("github")
    assert "2 entries" in out


def test_duplicate_add_refused(vault, term, capsys):
    add(vault, term)
    term.secrets = [MASTER]
    assert cli.main(["--vault", vault, "add", "github"]) == 1
    assert "already exists" in capsys.readouterr().err


def test_password_mismatch(vault, term, capsys):
    term.secrets = [MASTER, "one", "two"]
    term.lines = ["user"]
    assert cli.main(["--vault", vault, "add", "x"]) == 1
    assert "do not match" in capsys.readouterr().err


def test_init_twice_refused(vault, term, capsys):
    assert cli.main(["--vault", vault, "init"]) == 1
    assert "already exists" in capsys.readouterr().err


def test_short_master_refused(tmp_path, term, capsys):
    term.secrets = ["short", "short"]
    assert cli.main(["--vault", str(tmp_path / "v.json"), "init"]) == 1
    assert "at least 12" in capsys.readouterr().err


def test_delete_needs_confirmation(vault, term):
    add(vault, term)
    term.secrets = [MASTER]
    term.lines = ["n"]
    cli.main(["--vault", vault, "delete", "github"])
    term.secrets = [MASTER]
    term.lines = ["y"]
    assert cli.main(["--vault", vault, "delete", "github"]) == 0
    term.secrets = [MASTER]
    assert cli.main(["--vault", vault, "get", "github"]) == 1


def test_update(vault, term, capsys):
    add(vault, term)
    term.secrets = [MASTER, "new-pw", "new-pw"]
    term.lines = ["", "y", "new notes"]
    assert cli.main(["--vault", vault, "update", "github"]) == 0
    capsys.readouterr()
    term.secrets = [MASTER]
    cli.main(["--vault", vault, "get", "github"])
    out = capsys.readouterr().out
    assert "javid" in out and "new notes" in out


def test_change_master(vault, term):
    add(vault, term)
    term.secrets = [MASTER, "another long password", "another long password"]
    assert cli.main(["--vault", vault, "change-master"]) == 0
    term.secrets = [MASTER]
    assert cli.main(["--vault", vault, "list"]) == 1
    term.secrets = ["another long password"]
    assert cli.main(["--vault", vault, "list"]) == 0


def test_generate_copies_not_prints(term, capsys, tmp_path):
    assert cli.main(["--vault", str(tmp_path / "v.json"), "generate", "--length", "32"]) == 0
    assert term.clipboard is None  # cleared again
    out = capsys.readouterr().out
    assert "copied" in out


def test_add_generate(vault, term, capsys):
    term.secrets = [MASTER]
    term.lines = ["javid", ""]
    assert cli.main(["--vault", vault, "add", "--generate", "--length", "16", "site"]) == 0
    from pwmanager.vault import Vault
    with Vault.unlock(vault, MASTER) as v:
        pw = v.get("site")["password"]
    assert len(pw) == 16
    assert pw not in capsys.readouterr().out


@pytest.mark.parametrize("name", ["", "a b", "../etc", "x" * 65, "na;me", "é"])
def test_bad_entry_names(vault, name, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--vault", vault, "get", name])
    assert e.value.code == 2


@pytest.mark.parametrize("length", ["7", "129", "abc", " 20", "2_0", "+20", "-5", "1e3"])
def test_bad_lengths(length):
    with pytest.raises(SystemExit) as e:
        cli.main(["generate", "--length", length])
    assert e.value.code == 2


def test_bad_vault_path(term, capsys):
    assert cli.main(["--vault", "vault.txt", "list"]) == 1
    assert "must end in .json" in capsys.readouterr().err


def test_control_characters_refused(vault, term, capsys):
    term.secrets = [MASTER]
    term.lines = ["user\x1b[2J"]
    assert cli.main(["--vault", vault, "add", "x"]) == 1
    assert "control characters" in capsys.readouterr().err


def test_no_traceback_on_unexpected_error(vault, term, capsys, monkeypatch):
    def boom(*a):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(cli.Vault, "unlock", boom)
    term.secrets = [MASTER]
    assert cli.main(["--vault", vault, "list"]) == 1
    err = capsys.readouterr().err
    assert "secret detail" not in err and "Traceback" not in err


def test_missing_vault(tmp_path, term, capsys):
    term.secrets = [MASTER]
    assert cli.main(["--vault", str(tmp_path / "none.json"), "list"]) == 1
    assert "pwm init" in capsys.readouterr().err


def test_generated_password_has_all_classes():
    import string
    for _ in range(50):
        pw = cli.generate_password(8)
        assert len(pw) == 8
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in string.punctuation for c in pw)
