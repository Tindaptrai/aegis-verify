import uuid
from django.conf import settings
from django.db import models


class ScenarioPackageVersion(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scenario_id = models.CharField(max_length=7)
    version = models.CharField(max_length=128)
    sha256 = models.CharField(max_length=64)
    metadata = models.JSONField()
    validation = models.JSONField(default=dict)
    files = models.JSONField()
    storage_reference = models.CharField(max_length=40, unique=True)
    status = models.CharField(max_length=16, default='draft', choices=[(x, x) for x in ('draft', 'published', 'unpublished')])
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name='+')
    published_at = models.DateTimeField(null=True)
    published_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name='+')

    class Meta:
        default_permissions = ()
        constraints = [models.UniqueConstraint(fields=['scenario_id', 'version'], name='catalog_scenario_version_unique')]


class CatalogAuditQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError('catalog_audit_append_only')

    def delete(self):
        raise ValueError('catalog_audit_append_only')

    def bulk_create(self, objs, **kwargs):
        if kwargs.get('update_conflicts'):
            raise ValueError('catalog_audit_append_only')
        objs = list(objs)
        for obj in objs:
            obj.full_clean(exclude=['at'])
        return super().bulk_create(objs, **kwargs)


class CatalogAudit(models.Model):
    objects = CatalogAuditQuerySet.as_manager()
    package = models.ForeignKey(ScenarioPackageVersion, on_delete=models.PROTECT, related_name='audit')
    action = models.CharField(max_length=16, choices=[(x, x) for x in ('imported', 'published', 'unpublished')])
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT, related_name='+')
    sha256 = models.CharField(max_length=64)
    at = models.DateTimeField(auto_now_add=True)

    class Meta:
        default_permissions = ()
        base_manager_name = 'objects'
        ordering = ['pk']

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ValueError('catalog_audit_append_only')
        self.full_clean(exclude=['at'])
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError('catalog_audit_append_only')
