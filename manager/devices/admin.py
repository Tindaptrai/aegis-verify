"""Enrollment secrets and writes are intentionally absent from technical admin."""
from django.contrib import admin
from .models import EnrollmentAudit


@admin.register(EnrollmentAudit)
class EnrollmentAuditAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "actor_id", "code_id", "device_id")
    readonly_fields = ("created_at", "action", "actor_id", "code_id", "device_id")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
