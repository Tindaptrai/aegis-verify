"""Root-provisioned exact egress policy. Missing policy affects onboarding only."""
import json
import os
from pathlib import Path
import stat
from django.conf import settings
from aegis_verify.connectors.wazuh.onboarding import Target, ProbeError, origin, safe_address, validate_index, _unique


def parse_policy(value):
    try:
        if (type(value) is not dict or set(value) != {'schema_version', 'targets'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or type(value['targets']) is not list or not 1 <= len(value['targets']) <= 64):
            raise ValueError
        result = []
        for row in value['targets']:
            if type(row) is not dict or set(row) != {'origin', 'addresses', 'indices'}:
                raise ValueError
            origin(row['origin'])
            if any(type(row[key]) is not list or not 1 <= len(row[key]) <= 64 for key in ('addresses','indices')):
                raise ValueError
            addresses = tuple(safe_address(item) for item in row['addresses'])
            for item in row['indices']:
                validate_index(item)
            if len(set(addresses)) != len(addresses) or any(target.origin == row['origin'] for target in result):
                raise ValueError
            result.append(Target(row['origin'], addresses, tuple(row['indices'])))
        return tuple(result)
    except (ValueError, TypeError, KeyError, ProbeError):
        raise ProbeError('policy_denied') from None


def _read_policy():
    """Walk trusted root-owned ancestors with dirfd; never follow a link."""
    descriptor = None
    try:
        path = Path(settings.CONNECTION_POLICY)
        if os.name != 'posix' or not path.is_absolute() or '..' in path.parts:
            raise ValueError
        private = Path(settings.PRIVATE_ROOT).absolute()
        checkout = Path(__file__).absolute().parents[2]
        if path.is_relative_to(private) or path.is_relative_to(checkout):
            raise ValueError
        descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError
        file = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            info = os.fstat(file)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
                raise ValueError
            with os.fdopen(file, 'rb', closefd=False) as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError
            return raw
        finally:
            os.close(file)
    except (OSError, ValueError, TypeError, AttributeError):
        raise ProbeError('policy_denied') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def load_target(endpoint, index):
    try:
        targets = parse_policy(json.loads(_read_policy(), object_pairs_hook=_unique))
        for target in targets:
            if target.origin == endpoint and index in target.indices:
                return target
    except (ValueError, UnicodeError, RecursionError):
        pass
    raise ProbeError('policy_denied')
