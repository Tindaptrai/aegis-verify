"""Private configuration rejects unsafe input before access; no live services."""
import json
import os
from pathlib import Path

import pytest

from aegis_verify.dashboard import operations_config as config


@pytest.fixture
def setup_config(tmp_path, monkeypatch):
    root = tmp_path / 'private'
    root.mkdir(mode=0o700)
    ca = tmp_path / 'ca.pem'
    ca.write_text('synthetic-not-a-certificate')
    monkeypatch.setattr(config, '_check_private_acl', lambda path: None)
    data = dict(version=1, environment_id='fixture-lab', agent_ids=['012'],
                index='wazuh-alerts-*', output_root=str(root),
                indexer=dict(endpoint='https://indexer.invalid:9200', ca_file=str(ca)))
    def load(changes=None, env=None):
        content = {**data, **(changes or {})}
        path = tmp_path / 'operations.json'
        path.write_text(json.dumps(content))
        return config.load_operations_config(path, environ=env or {},
            reports_root=tmp_path / 'reports', static_root=None, source_root=tmp_path / 'source')
    return load, data


def test_credentials_are_separate_and_not_repr(setup_config):
    load, data = setup_config
    env = {'WAZUH_INDEXER_USERNAME': 'reader', 'WAZUH_INDEXER_PASSWORD': 'private-marker'}
    result = load({'server_api': data['indexer']}, env)
    assert result.indexer.username == 'reader'
    assert result.server_api is None
    assert result.agent_ids == ('012',)
    assert 'private-marker' not in repr(result)
    assert 'indexer.invalid' not in repr(result)


def test_missing_credentials_disable_source(setup_config):
    load, _ = setup_config
    assert load().indexer is None


@pytest.mark.parametrize('changes', [
    {'unknown': 1}, {'version': True}, {'version': 2}, {'agent_ids': []},
    {'agent_ids': ['012', '012']}, {'agent_ids': ['../x']}, {'agent_ids': [12]},
    {'agent_ids': [str(n) for n in range(101)]}, {'environment_id': ''},
    {'index': '../secret'}, {'index': '*'}, {'output_root': '//server/share'},
    {'output_root': 'FileSystem::C:/private'}, {'output_root': 'relative/path'},
    {'indexer': {'endpoint': 'http://source.invalid', 'ca_file': 'none'}},
])
def test_invalid_config_rejected(setup_config, changes):
    load, _ = setup_config
    with pytest.raises(config.OperationsError):
        load(changes)


@pytest.mark.parametrize('url', ['https://a.invalid/path', 'https://u:p@a.invalid',
    'https://a.invalid?x=1', 'https://a.invalid#x', 'https://a.invalid:0',
    'https://a.invalid:99999', 'https://a.invalid\\path'])
def test_endpoint_rejected_even_without_credentials(setup_config, url):
    load, data = setup_config
    with pytest.raises(config.OperationsError):
        load({'indexer': {**data['indexer'], 'endpoint': url}})


def test_overlapping_source_root_rejected(setup_config):
    load, data = setup_config
    with pytest.raises(config.OperationsError):
        load({'output_root': str(Path(data['output_root']).parent)})


@pytest.mark.parametrize('raw', ['{"version":1,"version":1}', '{bad', ' ' * 65537],
                         ids=['duplicate-key', 'malformed', 'oversized'])
def test_bad_document_rejected(tmp_path, raw):
    path = tmp_path / 'config.json'
    path.write_text(raw)
    with pytest.raises(config.OperationsError):
        config.load_operations_config(path, environ={}, reports_root=tmp_path,
                                      static_root=None, source_root=tmp_path)


@pytest.mark.parametrize('path', ['//no-server/share/config', 'https://example.invalid/a',
    'Registry::HKLM/foo', 'C:/a/../b', 'C:/a:stream', 'C:/a/*'])
def test_unsafe_syntax_rejected_before_stat(path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('filesystem accessed for rejected syntax')
    monkeypatch.setattr(Path, 'lstat', forbidden)
    with pytest.raises(config.OperationsError):
        config.local_path(path)


def test_acl_failure_is_closed(setup_config, monkeypatch):
    load, _ = setup_config
    def reject(path):
        raise config.OperationsError('private_root_required')
    monkeypatch.setattr(config, '_check_private_acl', reject)
    with pytest.raises(config.OperationsError, match='private_root_required'):
        load()


@pytest.mark.skipif(os.name == 'nt', reason='POSIX mode check')
def test_posix_public_root_rejected(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(config.OperationsError):
        config.verify_private_root(tmp_path, excluded_roots=())
    tmp_path.chmod(0o700)
    config.verify_private_root(tmp_path, excluded_roots=())


def test_symlink_root_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(config, '_check_private_acl', lambda path: None)
    target = tmp_path / 'target'
    target.mkdir()
    link = tmp_path / 'link'
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip('symlink privilege unavailable')
    with pytest.raises(config.OperationsError):
        config.verify_private_root(link, excluded_roots=())


@pytest.mark.parametrize('acl', [
    {'owner': 'S-1', 'current': 'S-2', 'rules': []},
    {'owner': 'S-1', 'current': 'S-1', 'rules': []},
    {'owner': 'S-1', 'current': 'S-1', 'rules': [
        {'sid': 'S-1', 'allow': True, 'rights': 2032127, 'inherit': 3, 'propagate': 0},
        {'sid': 'S-2', 'allow': True, 'rights': 1, 'inherit': 0, 'propagate': 0}]},
    {'owner': 'S-1', 'current': 'S-1', 'rules': [
        {'sid': 'S-1', 'allow': True, 'rights': 2032127, 'inherit': 0, 'propagate': 0}]},
])
def test_windows_acl_rejects_public_or_noninheriting_permissions(acl):
    with pytest.raises(config.OperationsError):
        config.validate_windows_acl(acl)


def test_windows_acl_owner_inheriting_full_control():
    config.validate_windows_acl({'owner': 'S-1', 'current': 'S-1', 'rules': [
        {'sid': 'S-1', 'allow': True, 'rights': 2032127, 'inherit': 3, 'propagate': 0}]})


@pytest.mark.skipif(os.name != 'nt', reason='Windows ACL integration')
def test_real_windows_private_acl_preflight(tmp_path):
    import base64
    import subprocess
    root = tmp_path / "literal '$; private"
    root.mkdir()
    # Only this newly-created test directory is changed, not the user's ACLs.
    setup = """
$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
[System.IO.Directory]::SetAccessControl($env:AEGIS_TEST_PRIVATE_ROOT, $acl)
@{default_owner=[System.Security.Principal.WindowsIdentity]::GetCurrent().Owner.Value; current=$sid.Value} | ConvertTo-Json -Compress
"""
    executable = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    result = subprocess.run([str(executable), '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode(setup.encode('utf-16le')).decode()],
        env={**os.environ, 'AEGIS_TEST_PRIVATE_ROOT': str(root)}, capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    config.verify_private_root(root, excluded_roots=())
    from aegis_verify.dashboard.operations_storage import JobStore
    from test_operations_storage import record
    identity = json.loads(result.stdout)
    if identity['default_owner'] != identity['current']:
        # Elevated CI creates children owned by Administrators, not the operator.
        # The supported non-elevated mode must not silently accept that ownership.
        with pytest.raises(config.OperationsError, match='private_root_required'):
            JobStore(root)
    else:
        store = JobStore(root)
        store.save(record())
        assert store.load() == [record()]
    (root / 'jobs').mkdir(exist_ok=True)
    # A protected, publicly-readable child remains unsafe even under private root.
    broaden_child = """
$ErrorActionPreference = 'Stop'
$path = [System.IO.Path]::Combine($env:AEGIS_TEST_PRIVATE_ROOT, 'jobs')
$acl = [System.IO.Directory]::GetAccessControl($path)
$acl.SetOwner([System.Security.Principal.WindowsIdentity]::GetCurrent().User)
$acl.SetAccessRuleProtection($true, $true)
$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($everyone, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
[System.IO.Directory]::SetAccessControl($path, $acl)
"""
    result = subprocess.run([str(executable), '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode(broaden_child.encode('utf-16le')).decode()],
        env={**os.environ, 'AEGIS_TEST_PRIVATE_ROOT': str(root)}, capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    with pytest.raises(config.OperationsError, match='private_root_required'):
        JobStore(root)
