"""Linux descriptor-relative private immutable files. No browser supplied paths.

Windows fails closed: the Linux service is the supported publication host.
Open directory descriptors anchor every mutation against parent/link races.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import uuid
from django.conf import settings


class StorageError(Exception):
    def __init__(self):
        super().__init__('storage_unavailable')


def _check(fd, *, directory):
    info = os.fstat(fd)
    if (info.st_uid != os.getuid() or info.st_mode & 0o077
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        raise StorageError()


def _name(identifier):
    return str(uuid.UUID(str(identifier)))


def paths(identifier):
    root = Path(settings.PRIVATE_ROOT) / 'connections' / _name(identifier)
    return root / 'config.json', root / 'ca.pem', root / 'output'


@contextmanager
def _root():
    fd = None
    try:
        if os.name != 'posix':
            raise StorageError()
        path = Path(settings.PRIVATE_ROOT)
        if not path.is_absolute() or '..' in path.parts:
            raise StorageError()
        fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for index, part in enumerate(path.parts[1:]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            # Shared sticky ancestors such as /tmp cannot rename another user's
            # private child; all other writable ancestors are refused.
            if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise StorageError()
        _check(fd, directory=True)
        try:
            os.mkdir('connections', mode=0o700, dir_fd=fd)
            os.fsync(fd)
        except FileExistsError:
            pass
        child = os.open('connections', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        os.close(fd)
        fd = child
        _check(fd, directory=True)
        yield fd
    except (OSError, ValueError, TypeError, AttributeError):
        raise StorageError() from None
    finally:
        if fd is not None:
            os.close(fd)


@contextmanager
def _directory(root, identifier):
    fd = os.open(_name(identifier), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
    try:
        _check(fd, directory=True)
        yield fd
    finally:
        os.close(fd)


def create(identifier, config, ca):
    with _root() as root:
        os.mkdir(_name(identifier), mode=0o700, dir_fd=root)
        with _directory(root, identifier) as directory:
            for name, raw in (('config.json', config), ('ca.pem', ca)):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            os.mkdir('output', mode=0o700, dir_fd=directory)
            os.fsync(directory)
        os.fsync(root)


def read(identifier):
    result = []
    with _root() as root, _directory(root, identifier) as directory:
        for name, limit in (('config.json', 16384), ('ca.pem', 65536)):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                _check(stream.fileno(), directory=False)
                value = stream.read(limit + 1)
                if len(value) > limit:
                    raise StorageError()
                result.append(value)
        output = os.open('output', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            _check(output, directory=True)
        finally:
            os.close(output)
    return tuple(result)


def cleanup(referenced, before):
    """Caller holds authority lock; only expired unpublished files may disappear.

    Unknown files or nonempty output roots are retained for operator inspection.
    No recursion, link following, or saved registration deletion is permitted.
    """
    with _root() as root:
        for name in os.listdir(root):
            try:
                if name in referenced or _name(name) != name:
                    continue
                with _directory(root, name) as directory:
                    if datetime.fromtimestamp(os.fstat(directory).st_mtime, timezone.utc) >= before:
                        continue
                    if set(os.listdir(directory)) - {'config.json', 'ca.pem', 'output'}:
                        continue
                    try:
                        output = os.open('output', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    except FileNotFoundError:
                        output = None
                    if output is not None:
                        try:
                            _check(output, directory=True)
                            if os.listdir(output):
                                continue
                        finally:
                            os.close(output)
                        os.rmdir('output', dir_fd=directory)
                    for filename in ('config.json', 'ca.pem'):
                        try:
                            os.unlink(filename, dir_fd=directory)
                        except FileNotFoundError:
                            pass
                os.rmdir(name, dir_fd=root)
            except (OSError, ValueError, StorageError):
                continue
        os.fsync(root)
