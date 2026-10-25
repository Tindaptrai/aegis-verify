"""Private, server-named immutable ZIP storage. Never extract package paths."""
import io
import os
import re
import stat
import tempfile
from hashlib import sha256
from pathlib import Path

from django.conf import settings
from .errors import CatalogError
from .package import validate_package

MAX_ZIP = 20 * 1024 * 1024


def _unsafe_link(path):
    details = path.lstat()
    return stat.S_ISLNK(details.st_mode) or bool(getattr(details, 'st_file_attributes', 0) & 0x400)


def _private_directory(path):
    details = path.stat()
    if os.name != 'nt' and (details.st_uid != os.getuid() or details.st_mode & 0o077):
        raise OSError


def read_upload(stream):
    try:
        parts, count = [], 0
        while True:
            chunk = stream.read(min(65536, MAX_ZIP + 1 - count))
            if not chunk:
                return b''.join(parts)
            if type(chunk) is not bytes:
                raise CatalogError('invalid_request')
            count += len(chunk)
            if count > MAX_ZIP:
                raise CatalogError('package_too_large', 413)
            parts.append(chunk)
    except OSError:
        raise CatalogError('storage_unavailable', 503) from None


def catalog_root():
    try:
        configured = Path(settings.PRIVATE_ROOT)
        if not configured.is_absolute() or not configured.is_dir():
            raise OSError
        if any(_unsafe_link(p) for p in (configured, *configured.parents)):
            raise OSError
        root = configured.resolve()
        checkout = Path(__file__).resolve().parents[2]
        if root.is_relative_to(checkout):
            raise OSError
        _private_directory(root)
        public = getattr(settings, 'STATIC_ROOT', None)
        if public and root.is_relative_to(Path(public).resolve()):
            raise OSError
        directory = root / 'catalog'
        directory.mkdir(mode=0o700, exist_ok=True)
        if _unsafe_link(directory) or not directory.is_dir():
            raise OSError
        _private_directory(directory)
        return directory
    except (OSError, AttributeError, TypeError, ValueError):
        raise CatalogError('storage_unavailable', 503) from None


def location(reference):
    if type(reference) is not str or not re.fullmatch(r'[0-9a-f-]{36}\.zip', reference):
        raise CatalogError('content_conflict', 409)
    path = catalog_root() / reference
    if path.exists() and _unsafe_link(path):
        raise CatalogError('content_conflict', 409)
    return path


def persist(reference, raw):
    destination = location(reference)
    temporary = None
    try:
        if destination.exists():
            raise CatalogError('content_conflict', 409)
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.staging-', delete=False) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
    except OSError:
        raise CatalogError('storage_unavailable', 503) from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def verify(row):
    try:
        with location(row.storage_reference).open('rb') as stream:
            raw = read_upload(stream)
    except OSError:
        raise CatalogError('storage_unavailable', 503) from None
    if sha256(raw).hexdigest() != row.sha256:
        raise CatalogError('content_conflict', 409)
    try:
        package = validate_package(io.BytesIO(raw))
    except CatalogError:
        raise CatalogError('content_conflict', 409) from None
    if package.metadata != row.metadata or package.files != row.files:
        raise CatalogError('content_conflict', 409)
    return package
