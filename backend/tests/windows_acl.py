"""Shared assertion for owner-only private directories and files on Windows (#110)."""

import pytest

from aegis_verify.dashboard import operations_config as config


def assert_owner_only(path, *, directory=True):
    """The DACL grants only the operator. In an elevated session the token's default
    owner is Administrators, so the owner check must still fail closed."""
    check = (lambda: config.verify_private_root(path, excluded_roots=())) if directory else (
        lambda: config.verify_private_file(path))
    data = config.read_windows_acl(path)
    if data['owner'] == data['current']:
        check()
        return
    config.validate_windows_acl({**data, 'owner': data['current']}, directory=directory)
    with pytest.raises(config.OperationsError, match='private_root_required'):
        check()
