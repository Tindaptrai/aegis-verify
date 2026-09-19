"""Strict local operations configuration. Credentials never cross the HTTP boundary."""
import base64
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

from ..intake.io import local_path as intake_path, read_local, decode_config
from ..intake.errors import IntakeError


class OperationsError(Exception):
    """Fixed diagnostic code only, never caller input or transport exceptions."""


@dataclass(frozen=True)
class ConnectionConfig:
    endpoint: str = field(repr=False)
    ca_file: Path = field(repr=False)
    username: str = field(repr=False)
    password: str = field(repr=False)


@dataclass(frozen=True)
class OperationsConfig:
    environment_id: str
    agent_ids: tuple[str, ...]
    index: str
    output_root: Path = field(repr=False)
    indexer: ConnectionConfig | None = field(default=None, repr=False)
    server_api: ConnectionConfig | None = field(default=None, repr=False)


def local_path(value, *, directory=False):
    """Stricter than intake: absolute only and reject traversal before normalization."""
    try:
        raw = os.fspath(value)
        if not isinstance(raw, str) or '..' in raw.replace('\\', '/').split('/') or not Path(raw).is_absolute():
            raise OperationsError('invalid_path')
        return intake_path(raw, directory=directory, stage='inputs')
    except (IntakeError, TypeError, ValueError, OSError):
        raise OperationsError('invalid_path') from None


def validate_windows_acl(data):
    try:
        owner, current, rules = data['owner'], data['current'], data['rules']
        if not isinstance(owner, str) or owner != current or not isinstance(rules, list) or not rules:
            raise ValueError
        inherited_owner_control = False
        for rule in rules:
            if rule['allow'] is not True or rule['sid'] != owner:
                raise ValueError
            if (rule['rights'] & 2032127 == 2032127 and rule['inherit'] == 3
                    and rule['propagate'] == 0):
                inherited_owner_control = True
        if not inherited_owner_control:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise OperationsError('private_root_required') from None


def _check_private_acl(path):
    if os.name != 'nt':
        info = path.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_mode & 0o700 != 0o700:
            raise OperationsError('private_root_required')
        return
    # Static code only. The literal path is child-process environment data, never
    # interpolated PowerShell source; no profile, policy changes or visible window.
    script = """+$ErrorActionPreference = 'Stop'
$acl = Get-Acl -LiteralPath $env:AEGIS_OPERATIONS_ACL_PATH
$sidType = [System.Security.Principal.SecurityIdentifier]
$owner = $acl.GetOwner($sidType).Value
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$rules = @($acl.GetAccessRules($true, $true, $sidType) | ForEach-Object {
    @{sid=$_.IdentityReference.Value; allow=($_.AccessControlType -eq 'Allow');
      rights=[int]$_.FileSystemRights; inherit=[int]$_.InheritanceFlags;
      propagate=[int]$_.PropagationFlags}
})
@{owner=$owner; current=$current; rules=$rules} | ConvertTo-Json -Depth 4 -Compress
"""
    executable = Path(os.environ.get('SystemRoot', '')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    try:
        result = subprocess.run([str(executable), '-NoLogo', '-NoProfile', '-NonInteractive',
            '-EncodedCommand', base64.b64encode(script.encode('utf-16le')).decode('ascii')],
            env={**os.environ, 'AEGIS_OPERATIONS_ACL_PATH': str(path)}, capture_output=True,
            timeout=10, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=True)
        if len(result.stdout) > 65536:
            raise ValueError
        validate_windows_acl(json.loads(result.stdout))
    except (OSError, ValueError, subprocess.SubprocessError):
        raise OperationsError('private_root_required') from None


def verify_private_root(root, *, excluded_roots):
    selected = local_path(root, directory=True)
    for excluded in excluded_roots:
        # Excluded directories need not exist yet; they are trusted server inputs.
        other = Path(excluded).resolve()
        if selected.is_relative_to(other) or other.is_relative_to(selected):
            raise OperationsError('invalid_output_root')
    _check_private_acl(selected)


def _connection(raw, prefix, environ):
    if raw is None:
        return None
    if type(raw) is not dict or set(raw) != {'endpoint', 'ca_file'}:
        raise OperationsError('invalid_config')
    endpoint = raw['endpoint']
    try:
        if type(endpoint) is not str or any(c.isspace() for c in endpoint) or '\\' in endpoint:
            raise ValueError
        url = urlsplit(endpoint)
        if (url.scheme != 'https' or not url.hostname or url.username is not None
                or url.password is not None or url.path not in ('', '/') or url.query or url.fragment
                or url.port == 0):
            raise ValueError
    except (ValueError, TypeError):
        raise OperationsError('invalid_config') from None
    ca = local_path(raw['ca_file'])
    username, password = environ.get(prefix + '_USERNAME'), environ.get(prefix + '_PASSWORD')
    if not username or not password:
        return None
    if (type(username) is not str or type(password) is not str or ':' in username
            or any(ord(c) < 32 for c in username + password)):
        raise OperationsError('invalid_credentials')
    return ConnectionConfig(endpoint, ca, username, password)


def load_operations_config(path, *, environ, reports_root, static_root, source_root):
    try:
        data = decode_config(read_local(local_path(path), limit=65536, stage='inputs'), stage='inputs')
    except IntakeError:
        raise OperationsError('invalid_config') from None
    required = {'version', 'environment_id', 'agent_ids', 'index', 'output_root'}
    if not required <= data.keys() or data.keys() - required - {'indexer', 'server_api'}:
        raise OperationsError('invalid_config')
    agents, environment, index = data['agent_ids'], data['environment_id'], data['index']
    if (type(data['version']) is not int or data['version'] != 1
            or type(agents) is not list or not 1 <= len(agents) <= 100
            or any(type(a) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', a) for a in agents)
            or len(set(agents)) != len(agents)
            or type(environment) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', environment)
            or type(index) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9._*-]{0,127}', index)
            or '..' in index):
        raise OperationsError('invalid_config')
    root = local_path(data['output_root'], directory=True)
    verify_private_root(root, excluded_roots=tuple(p for p in (reports_root, static_root, source_root) if p is not None))
    return OperationsConfig(environment, tuple(agents), index, root,
        _connection(data.get('indexer'), 'WAZUH_INDEXER', environ),
        _connection(data.get('server_api'), 'WAZUH_API', environ))
