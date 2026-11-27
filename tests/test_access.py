"""Per-user access control (A1-A4)."""

import os
import stat

import pytest
from conftest import MASTER, add

from pwmanager import access, cli, storage
from pwmanager.access import AccessDenied
from pwmanager.vault import Vault

POSIX = os.name == "posix"


def is_private(path):
    if POSIX:
        st = os.stat(path)
        return st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) & 0o077 == 0
    return access._read_security(path) == (True, False)


def make_too_open(path):
    """A normal new file: 0644 on Linux, inherited ACL (Users, SYSTEM ...) on Windows."""
    if POSIX:
        os.chmod(path, 0o644)


def pretend_other_owner(monkeypatch):
    if POSIX:
        uid = os.geteuid()
        monkeypatch.setattr(access.os, "geteuid", lambda: uid + 1)
    else:
        monkeypatch.setattr(access, "_read_security", lambda path: (False, False))


@pytest.fixture
def path(tmp_path):
    return storage.resolve_path(str(tmp_path / "vault.json"))


# ---------------------------------------------------------------- files

def test_current_user():
    assert access.current_user() == access.current_user()
    assert access.current_user() not in ("", "unknown")


def test_new_file_is_private(tmp_path):
    p = str(tmp_path / "new.log")
    fd, fixed = access.open_private(p, os.O_WRONLY)
    os.close(fd)
    assert not fixed
    assert is_private(p)


def test_too_open_file_is_fixed(tmp_path):
    p = tmp_path / "open.json"
    p.write_text("{}")
    make_too_open(str(p))
    assert access.check_file(str(p)) is True
    assert is_private(str(p))
    assert access.check_file(str(p)) is False


def test_file_of_another_user_is_refused(tmp_path, monkeypatch):
    p = tmp_path / "theirs.json"
    p.write_text("{}")
    pretend_other_owner(monkeypatch)
    with pytest.raises(AccessDenied, match="belongs to another user"):
        access.check_file(str(p))
    with pytest.raises(AccessDenied):
        access.open_private(str(p), os.O_RDONLY)


def test_open_private_refuses_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("x")
    link = tmp_path / "link"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks on this machine")
    with pytest.raises(AccessDenied):
        access.open_private(str(link), os.O_WRONLY)


def test_all_vault_files_are_private(vault, term):
    add(vault, term)
    folder = os.path.dirname(vault)
    for name in ("vault.json", "vault.json.lock", "pwm.log"):
        assert is_private(os.path.join(folder, name)), name


def test_old_vault_with_open_permissions_is_fixed(path):
    Vault.create(path, MASTER).lock()
    # Write it again the normal way, like Checkpoint 2 did on Windows
    # (inherited ACL), and with 0644 on Linux.
    data = open(path, "rb").read()
    os.remove(path)
    with open(path, "wb") as f:
        f.write(data)
    make_too_open(path)
    assert not is_private(path)
    Vault.unlock(path, MASTER).lock()
    assert is_private(path)


def test_vault_of_another_user_is_refused(vault, term, capsys, monkeypatch):
    pretend_other_owner(monkeypatch)
    term.secrets = [MASTER]
    assert cli.main(["--vault", vault, "list"]) == 1
    assert "belongs to another user" in capsys.readouterr().err


@pytest.mark.skipif(not POSIX, reason="file modes only on POSIX")
def test_existing_custom_folder_is_left_alone(tmp_path):
    folder = tmp_path / "shared"
    folder.mkdir(mode=0o755)
    os.chmod(folder, 0o755)
    Vault.create(str(folder / "vault.json"), MASTER).lock()
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o755
    assert is_private(str(folder / "vault.json"))


def test_default_folder_is_made_private(tmp_path, monkeypatch):
    folder = tmp_path / ".pwmanager"
    folder.mkdir()
    if POSIX:
        os.chmod(folder, 0o755)
    monkeypatch.setattr(storage, "DEFAULT_DIR", str(folder))
    storage.ensure_dir(str(folder / "vault.json"))
    assert is_private(str(folder))


# ---------------------------------------------------------------- record operations

RECORD_OPS = [
    ("names", ()), ("exists", ("a",)), ("get", ("a",)), ("add", ("b", "u", "p", "")),
    ("update", ("a",)), ("delete", ("a",)), ("save", ()), ("change_master", (MASTER,)),
]


@pytest.mark.parametrize("op, args", RECORD_OPS)
def test_record_operations_refused_when_locked(path, op, args):
    v = Vault.create(path, MASTER)
    v.add("a", "u", "p", "")
    v.lock()
    with pytest.raises(AccessDenied, match="locked"):
        getattr(v, op)(*args)


@pytest.mark.parametrize("op, args", RECORD_OPS)
def test_record_operations_refused_for_another_user(path, op, args, monkeypatch):
    with Vault.create(path, MASTER) as v:
        v.add("a", "u", "p", "")
        monkeypatch.setattr(access, "current_user", lambda: "someone-else")
        with pytest.raises(AccessDenied, match="different user"):
            getattr(v, op)(*args)


# ---------------------------------------------------------------- vault lock

def test_second_command_cannot_use_the_vault_at_the_same_time(path):
    Vault.create(path, MASTER).lock()
    first = Vault.unlock(path, MASTER)
    with pytest.raises(storage.StorageError, match="another pwm command"):
        Vault.unlock(path, MASTER)
    first.lock()
    Vault.unlock(path, MASTER).lock()
