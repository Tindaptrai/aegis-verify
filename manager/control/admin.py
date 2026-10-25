from django.contrib import admin, messages
from django.db import transaction
from .models import Device, RunnerRelease, Job, AuditEntry
from .jobs import approve_job, reconcile_job, cancel_job
from .execution_ownership import lock_human_authority, lock_dispatch, lock_device_ownership
from accounts.permissions import require_product_admin


class OwnerAdmin(admin.ModelAdmin):
    def has_module_permission(self, request): return request.user.is_active and request.user.is_superuser
    def has_view_permission(self, request, obj=None): return self.has_module_permission(request)
    def has_add_permission(self, request): return self.has_module_permission(request)
    def has_change_permission(self, request, obj=None): return self.has_module_permission(request)
    def has_delete_permission(self, request, obj=None): return False


@admin.register(Device)
class DeviceAdmin(OwnerAdmin):
    list_display = ("id", "environment_id", "generation", "revoked")
    readonly_fields = ("archived_at", "archived_by_id", "reported_ips", "ip_collection_status",
                       "reported_ips_truncated", "reported_ips_received_at", "observed_ip",
                       "observed_ip_received_at", "reported_agent_version", "last_heartbeat_at")

    def get_readonly_fields(self, request, obj=None):
        if obj and obj.connection_kind == 'paired_presence':
            return self.readonly_fields + ('connection_kind','generation','certificate_sha256','environment_id',
                'wazuh_agent_id','revoked','certificate_not_before','certificate_expires_at')
        return self.readonly_fields + (("revoked",) if obj and obj.archived_at is not None else ())

    @transaction.atomic
    def save_model(self, request, obj, form, change):
        lock_human_authority()
        require_product_admin(request.user)
        lock_dispatch()
        if not change and obj.connection_kind != 'legacy_v1':
            raise ValueError('Paired identity requires enrollment')
        if change:
            lock_device_ownership(obj.pk)
            # A form loaded before archive/heartbeat must not write its stale
            # readonly snapshot back over a subsequently committed mutation.
            current = Device.objects.select_for_update().get(pk=obj.pk)
            if current.connection_kind == 'legacy_v1' and obj.connection_kind != 'legacy_v1':
                raise ValueError('Paired identity requires enrollment')
            for name in self.get_readonly_fields(request,current):
                setattr(obj, name, getattr(current, name))
            if current.archived_at is not None:
                obj.revoked = True
        super().save_model(request, obj, form, change)


@admin.register(RunnerRelease)
class ReleaseAdmin(OwnerAdmin):
    def has_change_permission(self, request, obj=None):
        return super().has_change_permission(request,obj) and (obj is None or not obj.job_set.exists() and not obj.deviceexecutionbinding_set.exists())

    @transaction.atomic
    def save_model(self, request, obj, form, change):
        lock_human_authority()
        require_product_admin(request.user)
        lock_dispatch()
        if change:
            current=RunnerRelease.objects.select_for_update().get(pk=obj.pk)
            if current.job_set.exists() or current.deviceexecutionbinding_set.exists():
                raise ValueError('Referenced release is immutable')
        super().save_model(request,obj,form,change)


@admin.register(Job)
class JobAdmin(OwnerAdmin):
    list_display = ("id", "device", "execution_state", "collection_state", "error_code")
    actions = ("approve", "cancel", "reconcile")
    readonly_fields = ("id", "execution_state", "collection_state", "report", "error_code", "payload_sha256", "envelope", "receipt", "receipt_bytes", "approval_id", "approved_generation", "approved_wazuh_agent_id", "evaluation_bindings", "created_at", "started_authorized_at",
        "protocol_family", "binding", "approval_snapshot", "preview", "envelope_bytes", "signed_payload_bytes", "job_sha256",
        "start_request_id", "start_request_bytes", "start_request_sha256", "start_ack_bytes", "terminal_receipt_id",
        "terminal_receipt_bytes", "receipt_ack_bytes", "finished_at")
    def get_readonly_fields(self, request, obj=None):
        if obj and obj.execution_state != "draft": return tuple(f.name for f in self.model._meta.fields)
        return self.readonly_fields
    @admin.action(description="Approve selected bounded jobs")
    def approve(self, request, queryset):
        for job in queryset:
            try: approve_job(job.pk,request.user)
            except (ValueError, OSError) as exc: self.message_user(request,"Approval rejected: verify private release pins and job bounds",messages.ERROR)
    @admin.action(description="Cancel selected unstarted jobs")
    def cancel(self, request, queryset):
        for job in queryset:
            try: cancel_job(job.pk,request.user)
            except ValueError: self.message_user(request,"Only unstarted jobs can be cancelled",messages.ERROR)
    @admin.action(description="Reconcile selected jobs (owner has checked agent journal)")
    def reconcile(self, request, queryset):
        for job in queryset:
            try: reconcile_job(job.pk,request.user)
            except ValueError: self.message_user(request,"Cannot reconcile draft or active collection",messages.ERROR)


@admin.register(AuditEntry)
class AuditAdmin(OwnerAdmin):
    list_display = ("created_at", "actor", "action", "job")
    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    readonly_fields = ("created_at", "actor", "action", "job")


from .execution_models import (DeviceExecutionBinding, RegisteredExecutionConnection, JobApprovalSnapshot,
    ExecutionPreview, ExecutionIdempotency, ExecutionTargetOwnership, ExecutionOwnershipAudit,
    BindingAdmissionAudit, LocalExecutionReadiness, CollectionWorkerLease, ExecutionOwnerDecision)


class ExecutionAuthorityAdmin(OwnerAdmin):
    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    def get_readonly_fields(self, request, obj=None): return tuple(f.name for f in self.model._meta.fields)


for authority in (DeviceExecutionBinding, RegisteredExecutionConnection, JobApprovalSnapshot,
                  ExecutionPreview, ExecutionIdempotency, ExecutionTargetOwnership, ExecutionOwnershipAudit,
                  BindingAdmissionAudit, LocalExecutionReadiness, CollectionWorkerLease, ExecutionOwnerDecision):
    admin.site.register(authority, ExecutionAuthorityAdmin)
