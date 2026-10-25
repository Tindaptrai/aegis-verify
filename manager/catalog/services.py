"""Catalog writes serialize with account authority changes and preserve bytes."""
import io
import re
import uuid
from django.db import transaction
from django.utils import timezone
from accounts.models import AccountMutationLock
from accounts.permissions import require_product_permission
from .errors import CatalogError
from .models import CatalogAudit, ScenarioPackageVersion
from .package import validate_package
from . import storage


def _authorize(actor, permission):
    AccountMutationLock.objects.select_for_update().get(pk=1)
    return require_product_permission(actor, permission)


def get_package(package_id, *, locked=False):
    rows = ScenarioPackageVersion.objects.select_related('created_by', 'published_by')
    if locked:
        rows = rows.select_for_update(of=('self',))
    try:
        return rows.get(pk=package_id)
    except ScenarioPackageVersion.DoesNotExist:
        raise CatalogError('package_not_found', 404) from None


def import_package(*, actor, stream):
    owned_path = None
    try:
        with transaction.atomic():
            actor = _authorize(actor, 'import_scenarios')
            raw = storage.read_upload(stream)
            package = validate_package(io.BytesIO(raw))
            metadata = package.metadata
            existing = ScenarioPackageVersion.objects.filter(scenario_id=metadata['scenario_id'], version=metadata['version']).first()
            if existing is not None:
                if existing.sha256 != package.sha256:
                    raise CatalogError('version_conflict', 409)
                storage.verify(existing)
                return existing, False
            identifier = uuid.uuid4()
            reference = str(identifier) + '.zip'
            storage.persist(reference, raw)
            owned_path = storage.location(reference)
            row = ScenarioPackageVersion.objects.create(id=identifier, scenario_id=metadata['scenario_id'], version=metadata['version'],
                sha256=package.sha256, metadata=metadata, files=package.files, validation={'valid': True, 'codes': []},
                storage_reference=reference, created_by=actor)
            CatalogAudit.objects.create(package=row, action='imported', actor=actor, sha256=row.sha256)
        return row, True
    except BaseException:
        if owned_path is not None:
            owned_path.unlink(missing_ok=True)
        raise


def _lifecycle(*, actor, package_id, sha256, publishing):
    if type(sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', sha256):
        raise CatalogError('invalid_request')
    with transaction.atomic():
        actor = _authorize(actor, 'publish_scenarios')
        row = get_package(package_id, locked=True)
        if row.sha256 != sha256:
            raise CatalogError('content_conflict', 409)
        storage.verify(row)
        desired = 'published' if publishing else 'unpublished'
        if row.status == desired:
            return row
        if not publishing and row.status != 'published':
            raise CatalogError('content_conflict', 409)
        row.status = desired
        fields = ['status']
        if publishing:
            row.published_at, row.published_by = timezone.now(), actor
            fields += ['published_at', 'published_by']
        row.save(update_fields=fields)
        CatalogAudit.objects.create(package=row, action='published' if publishing else 'unpublished', actor=actor, sha256=row.sha256)
        return row


def publish_package(*, actor, package_id, sha256):
    return _lifecycle(actor=actor, package_id=package_id, sha256=sha256, publishing=True)


def unpublish_package(*, actor, package_id, sha256):
    return _lifecycle(actor=actor, package_id=package_id, sha256=sha256, publishing=False)
