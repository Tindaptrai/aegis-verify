"""Owned-directory, no-overwrite transport IO. No network or automatic cleanup."""

import os
from pathlib import Path

from ..intake.io import local_path, read_local, _path_text, _same_snapshot
from ..intake.errors import IntakeError


def strict_path(path):
    raw = _path_text(path, stage='inputs')
    if any(part in {'.', '..'} for part in raw.replace('\\', '/').split('/')):
        raise IntakeError('invalid_path')
    return Path(raw)


def checked_file(path):
    selected = local_path(strict_path(path))
    if selected.stat().st_nlink != 1:
        raise IntakeError('invalid_path')
    return selected


def read_file(path, limit):
    selected = checked_file(path)
    before = selected.stat()
    raw = read_local(selected, limit=limit, stage='evidence')
    after = checked_file(path).stat()
    if not _same_snapshot(before, after) or len(raw) != after.st_size:
        raise IntakeError('input_io')
    return raw


def output_target(path):
    path = strict_path(path)
    parent = local_path(path.parent, directory=True)
    if any(os.path.lexists(ancestor / '.git') for ancestor in (parent, *parent.parents)):
        raise IntakeError('invalid_path')
    target = parent / path.name
    if os.path.lexists(target):
        raise IntakeError('invalid_path')
    return target


def write_file(root, relative, raw):
    # Only generated relative paths reach this helper, never manifest/user paths.
    local_path(root, directory=True)
    target = root / relative
    local_path(target.parent, directory=True)
    with target.open('xb') as stream:
        os.chmod(target, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if read_file(target, len(raw)) != raw:
        raise IntakeError('input_io')


def inventory(root):
    root = local_path(strict_path(root), directory=True)
    names = set()
    for entry in root.iterdir():
        if entry.name in {'snapshots', 'documents'}:
            directory = local_path(entry, directory=True)
            for child in directory.iterdir():
                checked_file(child)
                names.add(entry.name + '/' + child.name)
                if len(names) > 138:
                    raise IntakeError('resource_limit')
        else:
            checked_file(entry)
            names.add(entry.name)
        if len(names) > 138:
            raise IntakeError('resource_limit')
    return names
