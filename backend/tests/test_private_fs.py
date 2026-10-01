"""mkdir_private creates one owner-only directory and never repairs an existing one (#110)."""

import os

import pytest

from aegis_verify import private_fs
from aegis_verify.dashboard import operations_config as config
from windows_acl import assert_owner_only


def test_creates_new_directory_only(tmp_path):
    target = private_fs.mkdir_private(tmp_path / 'new')
    assert target.is_dir()
    with pytest.raises(FileExistsError):
        private_fs.mkdir_private(target)
    assert private_fs.mkdir_private(target, exist_ok=True) == target
    (tmp_path / 'file').write_bytes(b'')
    with pytest.raises(FileExistsError):
        private_fs.mkdir_private(tmp_path / 'file', exist_ok=True)
    with pytest.raises(FileNotFoundError):
        private_fs.mkdir_private(tmp_path / 'missing' / 'child')


@pytest.mark.skipif(os.name == 'nt', reason='POSIX mode check')
def test_posix_directory_is_owner_only(tmp_path):
    assert private_fs.mkdir_private(tmp_path / 'new').stat().st_mode & 0o077 == 0


@pytest.mark.skipif(os.name != 'nt', reason='Windows ACL integration')
def test_windows_directory_child_and_file_are_owner_only(tmp_path):
    target = private_fs.mkdir_private(tmp_path / 'new')
    assert_owner_only(target)
    child = private_fs.mkdir_private(target / 'child')
    assert_owner_only(child)
    (child / 'evidence.json').write_bytes(b'{}')
    assert_owner_only(child / 'evidence.json', directory=False)


@pytest.mark.skipif(os.name != 'nt', reason='Windows ACL integration')
def test_windows_acl_check_never_uses_a_relative_powershell(tmp_path, monkeypatch):
    target = private_fs.mkdir_private(tmp_path / 'new')
    monkeypatch.delenv('SystemRoot', raising=False)
    with pytest.raises(config.OperationsError, match='private_root_required'):
        config.verify_private_root(target, excluded_roots=())
