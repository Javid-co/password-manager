import os
import stat

import pytest

from pwmanager import storage
from pwmanager.storage import StorageError, VaultNotFound


def make_symlink(target, link):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks on this machine")


def test_write_then_read(tmp_path):
    path = storage.resolve_path(str(tmp_path / "v" / "vault.json"))
    storage.write_vault(path, {"a": 1})
    assert storage.read_vault(path) == {"a": 1}
    storage.write_vault(path, {"a": 2})
    assert storage.read_vault(path) == {"a": 2}


def test_no_temp_files_left(tmp_path):
    path = storage.resolve_path(str(tmp_path / "vault.json"))
    storage.write_vault(path, {"a": 1})
    storage.write_vault(path, {"a": 2})
    assert os.listdir(tmp_path) == ["vault.json"]


def test_failed_write_keeps_old_vault(tmp_path):
    path = storage.resolve_path(str(tmp_path / "vault.json"))
    storage.write_vault(path, {"a": 1})
    with pytest.raises(TypeError):
        storage.write_vault(path, {"a": object()})  # cannot be turned into JSON
    assert storage.read_vault(path) == {"a": 1}
    assert os.listdir(tmp_path) == ["vault.json"]


@pytest.mark.skipif(os.name != "posix", reason="file modes only on POSIX")
def test_permissions(tmp_path):
    path = storage.resolve_path(str(tmp_path / "v" / "vault.json"))
    storage.write_vault(path, {"a": 1})
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700


def test_missing_vault(tmp_path):
    with pytest.raises(VaultNotFound):
        storage.read_vault(str(tmp_path / "vault.json"))


@pytest.mark.parametrize("bad", ["", "vault.txt", "a\x00b.json", "x" * 5000 + ".json"])
def test_bad_paths(bad):
    with pytest.raises(StorageError):
        storage.resolve_path(bad)


def test_folder_as_path(tmp_path):
    (tmp_path / "dir.json").mkdir()
    with pytest.raises(StorageError):
        storage.resolve_path(str(tmp_path / "dir.json"))


def test_traversal_is_resolved(tmp_path):
    (tmp_path / "a").mkdir()
    path = storage.resolve_path(str(tmp_path / "a" / ".." / "vault.json"))
    assert path == os.path.realpath(str(tmp_path / "vault.json"))


def test_symlink_vault_refused(tmp_path):
    real = tmp_path / "other.json"
    real.write_text("{}")
    link = tmp_path / "vault.json"
    make_symlink(real, link)
    with pytest.raises(StorageError):
        storage.read_vault(str(link))
    with pytest.raises(StorageError):
        storage.write_vault(str(link), {"a": 1})
    assert real.read_text() == "{}"


def test_garbage_file(tmp_path):
    path = tmp_path / "vault.json"
    path.write_bytes(b"\xff\xfe not json")
    with pytest.raises(StorageError, match="could not unlock vault"):
        storage.read_vault(str(path))


def test_too_large(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "MAX_VAULT_SIZE", 10)
    path = tmp_path / "vault.json"
    path.write_text('{"a": "0123456789"}')
    with pytest.raises(StorageError, match="too large"):
        storage.read_vault(str(path))
