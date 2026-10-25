"""Protected local connection registration; private references never become DTOs."""
from hashlib import sha256
import os
from pathlib import Path
import uuid
from django.db import transaction
from accounts.permissions import require_product_permission
from aegis_verify.intake.io import local_path, read_local
from .collection import load_connection
from .worker import validate_output_root
from .execution_contracts import ExecutionError, _field
from .execution_models import RegisteredExecutionConnection
from .execution_ownership import lock_human_authority, lock_dispatch, require_idle


def root_fingerprint(root):
    return sha256(os.path.normcase(str(root)).encode()).hexdigest()


def private_connection(config_path):
    try:
        path = Path(config_path)
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError
        path = local_path(path, stage='inputs')
        before = read_local(path, limit=16384, stage='inputs')
        connection = load_connection(path)
        if read_local(path, limit=16384, stage='inputs') != before:
            raise ValueError
        return path, connection, sha256(before).hexdigest()
    except Exception:
        raise ValueError('invalid_private_execution_connection') from None


@transaction.atomic
def register_execution_connection(actor, *, connection_id=None, expected_revision, config_path, output_root):
    lock_human_authority()
    actor = require_product_permission(actor, 'manage_connections')
    lock_dispatch()
    require_idle()
    if connection_id is None:
        if expected_revision is not None: raise ExecutionError('binding_conflict')
        connection_id, revision = uuid.uuid4(), 1
    else:
        try: _field('connection_id', connection_id)
        except (ValueError, TypeError): raise ExecutionError('binding_conflict') from None
        latest = RegisteredExecutionConnection.objects.filter(connection_id=connection_id).order_by('-revision').first()
        if latest is None or type(expected_revision) is not int or latest.revision != expected_revision:
            raise ExecutionError('binding_conflict')
        connection_id = latest.connection_id
        revision = latest.revision + 1
    try:
        path, _, digest = private_connection(config_path)
        root = validate_output_root(output_root)
        return RegisteredExecutionConnection.objects.create(connection_id=connection_id, revision=revision,
            config_path=str(path), config_sha256=digest, output_root_path=str(root),
            output_root_fingerprint=root_fingerprint(root), reviewed_by=actor)
    except Exception:
        raise ExecutionError('execution_unavailable') from None


def resolve_execution_connection(connection_id, revision):
    """Resolve historical exact revision; caller decides whether current is required."""
    try:
        if type(revision) is not int or revision < 1: raise ValueError
        row = RegisteredExecutionConnection.objects.get(connection_id=connection_id, revision=revision)
        if not row.output_root_path: raise ValueError
        _, connection, digest = private_connection(row.config_path)
        root = validate_output_root(row.output_root_path)
        if digest != row.config_sha256 or root_fingerprint(root) != row.output_root_fingerprint:
            raise ValueError
        return connection, root
    except Exception:
        raise ValueError('invalid_private_execution_connection') from None
