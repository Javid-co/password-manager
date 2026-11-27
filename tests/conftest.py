"""Shared test helpers. getpass, input and the clipboard are replaced with fakes."""

import pytest

from pwmanager import audit, cli, clipboard
from pwmanager.secmem import private_copy

MASTER = "a long master password"


class FakeTerminal:
    def __init__(self, monkeypatch):
        self.secrets = []
        self.lines = []
        self.clipboard = None
        self.typed = []  # every secret handed to the program, to check it was wiped
        monkeypatch.setattr(cli.getpass, "getpass", self._getpass)
        monkeypatch.setattr("builtins.input", lambda prompt="": self.lines.pop(0))
        monkeypatch.setattr(clipboard, "_copy", self._copy)
        monkeypatch.setattr(clipboard, "_paste",
                            lambda: private_copy(self.clipboard) if self.clipboard else "")
        monkeypatch.setattr(clipboard, "_clear", self._clear)
        monkeypatch.setattr(cli, "CLIPBOARD_SECONDS", 0)
        monkeypatch.setattr(cli, "FAIL_DELAY_SECONDS", 0)

    def _getpass(self, prompt=""):
        # Real getpass returns a new string every time, and the CLI wipes it
        # after use. A copy is returned here so the test constants are not wiped.
        value = private_copy(self.secrets.pop(0))
        self.typed.append(value)
        return value

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


@pytest.fixture(autouse=True)
def _reset_audit():
    yield
    audit.shutdown()


def add(path, term, name="github", user="javid", pw="Secret-pw-1", notes=""):
    term.secrets = [MASTER, pw, pw]
    term.lines = [user, notes]
    return cli.main(["--vault", path, "add", name])
