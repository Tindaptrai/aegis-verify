import uuid
from datetime import timedelta
from itertools import product
from urllib.parse import quote
from unittest.mock import patch, PropertyMock

from django.contrib.admin.sites import AdminSite
from django.db import IntegrityError, transaction
from django.test import RequestFactory
from django.utils import timezone

from control.admin import DeviceAdmin
from control.models import Device, Job, RunnerRelease
from control.models import AuditEntry
from devices.models import EnrollmentAudit, PairingCode
from .helpers import PairingCase, component


class ArchiveTests(PairingCase):
    def test_v2_cancelled_lease_requires_owner_reconciliation_before_archive(self):
        from devices.archive import archive_block_reason
        device=Device.objects.create(environment_id='synthetic',certificate_sha256='b'*64,connection_kind='paired_presence')
        release=RunnerRelease.objects.create()
        now=timezone.now()
        job=Job.objects.create(device=device,release=release,protocol_family='windows_execution_v2',execution_state='cancelled',
            not_before=now,expires_at=now,collection_start=now,collection_end=now)
        AuditEntry.objects.create(job=job,action='leased',actor=str(device.pk))
        self.assertEqual(archive_block_reason(device),'device_busy')
        job.collection_state='reconciled'; job.save(update_fields=['collection_state'])
        self.assertIsNone(archive_block_reason(device))

    def enrolled(self):
        self.initialize()
        return component(self, "services").enroll_device(self.enrollment())

    def test_archive_retains_identity_and_history_once(self):
        enrolled = self.enrolled()
        device = Device.objects.get()
        before = (device.certificate_sha256, device.generation)
        client = self.login_human(self.admin)
        route = f"/api/v2/devices/{device.pk}/archive"
        self.assertEqual(self.human_post(client, route, {}).status_code, 204)
        device.refresh_from_db()
        original = (device.archived_at, device.archived_by_id)
        self.assertTrue(device.revoked)
        self.assertEqual(device.archived_by_id, self.admin.pk)
        self.assertIsNotNone(device.archived_at)
        self.assertEqual(self.human_post(self.login_human(self.owner), route, {}).status_code, 204)
        device.refresh_from_db()
        self.assertEqual(original, (device.archived_at, device.archived_by_id))
        self.assertEqual(before, (device.certificate_sha256, device.generation))
        self.assertEqual(EnrollmentAudit.objects.filter(action="device_archived").count(), 1)
        self.assertEqual(EnrollmentAudit.objects.filter(action="device_revoked").count(), 1)
        self.assertIsNotNone(PairingCode.objects.get().consumed_at)
        self.assertEqual(PairingCode.objects.get().consumed_device_id, device.pk)
        for route in ("/api/v1/devices", "/api/v2/devices"):
            self.assertEqual(client.get(route).json()["count"], 0)
        self.assertEqual(client.get("/api/v2/devices?scope=archived").json()["count"], 1)
        self.assertEqual(client.get(f"/api/v2/devices/{device.pk}").json()["status"], "archived")
        rows = client.get(f"/api/v2/devices/{device.pk}/history").json()["results"]
        self.assertEqual([r["action"] for r in rows], ["device_archived", "device_revoked", "device_enrolled", "pairing_code_created"])
        self.assertEqual(self.client.post("/agent/v2/heartbeat", {"protocol": "2.0", "device_id": str(device.pk), "generation": 1},
            content_type="application/json", HTTP_X_FORWARDED_PROTO="https", HTTP_X_AEGIS_CLIENT_VERIFY="SUCCESS",
            HTTP_X_AEGIS_CLIENT_CERT=quote(enrolled["certificate_pem"], safe="")).status_code, 403)
        device.refresh_from_db()
        self.assertIsNone(device.last_heartbeat_at)

    def test_permissions_csrf_missing_device_and_closed_body(self):
        device = Device.objects.create(environment_id="synthetic", certificate_sha256="a"*64, connection_kind="paired_presence")
        route = f"/api/v2/devices/{device.pk}/archive"
        for actor in (self.viewer, self.operator):
            self.assertEqual(self.human_post(self.login_human(actor), route, {}).status_code, 403)
        client = self.login_human(self.admin)
        self.assertEqual(client.post(route, {}, content_type="application/json").status_code, 403)
        for body in ({"extra": True}, [], None):
            response = self.human_post(client, route, body if body is not None else "null")
            self.assertEqual(response.status_code, 400)
        missing = self.human_post(client, f"/api/v2/devices/{uuid.uuid4()}/archive", {})
        self.assertEqual((missing.status_code, missing.json()["error"]["code"]), (404, "device_not_found"))
        self.admin.groups.clear()
        self.assertEqual(self.human_post(client, route, {}).status_code, 403)
        type(self.owner).objects.filter(pk=self.owner.pk).update(is_active=False)
        with self.assertRaises(PermissionError):
            component(self, "archive").archive_device(actor=self.owner, device_id=device.pk)
        device.refresh_from_db()
        self.assertFalse(device.revoked)

    def test_all_job_state_combinations_and_legacy_denial(self):
        archive = component(self, "archive")
        device = Device.objects.create(environment_id="synthetic", certificate_sha256="a"*64, connection_kind="paired_presence")
        release = RunnerRelease.objects.create()
        now = timezone.now()
        job = Job.objects.create(device=device, release=release, not_before=now, expires_at=now+timedelta(minutes=1), collection_start=now, collection_end=now)
        allowed = {
            "draft": {"pending", "evaluated", "empty", "reconciled"},
            "cancelled": {"pending", "evaluated", "empty", "reconciled"},
            "expired": {"pending", "evaluated", "empty", "reconciled"},
            "succeeded": {"evaluated", "empty", "reconciled"},
            "failed": {"evaluated", "empty", "reconciled"},
            "execution_unknown": {"evaluated", "empty", "reconciled"},
        }
        for execution, collection in product((*allowed, "queued", "leased", "started", "unexpected"), ("pending", "evaluated", "empty", "reconciled", "collecting", "failed", "unexpected")):
            with self.subTest(execution=execution, collection=collection):
                job.execution_state, job.collection_state = execution, collection
                job.save()
                permitted = collection in allowed.get(execution, set())
                self.assertEqual(archive.archive_block_reason(device), None if permitted else "device_busy")
                if permitted:
                    # Roll back only this successful trial, retaining the same
                    # synthetic job for the remaining acceptance matrix.
                    with transaction.atomic():
                        archive.archive_device(actor=self.admin, device_id=device.pk)
                        archived = Device.objects.get(pk=device.pk)
                        self.assertTrue(archived.revoked)
                        self.assertIsNotNone(archived.archived_at)
                        job.refresh_from_db()
                        self.assertEqual((job.execution_state, job.collection_state), (execution, collection))
                        transaction.set_rollback(True)
                else:
                    with self.assertRaises(component(self, "contracts").DeviceError) as denied:
                        archive.archive_device(actor=self.admin, device_id=device.pk)
                    self.assertEqual(denied.exception.code, "device_busy")
        device.connection_kind = "legacy_v1"
        device.save()
        with self.assertRaises(component(self, "contracts").DeviceError) as denied:
            archive.archive_device(actor=self.admin, device_id=device.pk)
        self.assertEqual(denied.exception.code, "device_conflict")

    def test_constraint_admin_and_atomic_audit_failure(self):
        archive = component(self, "archive")
        device = Device.objects.create(environment_id="synthetic", certificate_sha256="a"*64, connection_kind="paired_presence")
        with self.assertRaises(IntegrityError), transaction.atomic():
            Device.objects.filter(pk=device.pk).update(archived_at=timezone.now())
        readonly = DeviceAdmin(Device, AdminSite()).get_readonly_fields(RequestFactory().get("/"), device)
        self.assertTrue({"archived_at", "archived_by_id", "reported_ips", "observed_ip"}.issubset(readonly))
        with patch("devices.archive.EnrollmentAudit.objects.create", side_effect=RuntimeError("synthetic audit failure")):
            with self.assertRaises(RuntimeError):
                archive.archive_device(actor=self.admin, device_id=device.pk)
        device.refresh_from_db()
        self.assertFalse(device.revoked)
        self.assertIsNone(device.archived_at)
        archive.archive_device(actor=self.admin, device_id=device.pk)
        device.refresh_from_db()
        self.assertIn("revoked", DeviceAdmin(Device, AdminSite()).get_readonly_fields(RequestFactory().get("/"), device))
        self.assertFalse(DeviceAdmin(Device, AdminSite()).has_delete_permission(RequestFactory().get("/"), device))

    def test_previously_revoked_device_preserves_history(self):
        archive = component(self, "archive")
        device = Device.objects.create(environment_id="synthetic", certificate_sha256="a"*64, connection_kind="paired_presence", revoked=True)
        archive.archive_device(actor=self.admin, device_id=device.pk)
        self.assertFalse(EnrollmentAudit.objects.filter(action="device_revoked").exists())
        audit = EnrollmentAudit.objects.get(action="device_archived")
        with self.assertRaises(ValueError):
            audit.delete()
        with self.assertRaises(ValueError):
            EnrollmentAudit.objects.filter(pk=audit.pk).update(actor_id=999)

    def test_archive_keeps_snapshot_job_report_and_consumed_code(self):
        from devices.archive import archive_device
        self.enrolled()
        device = Device.objects.get()
        device.reported_ips = ["192.0.2.10"]
        device.ip_collection_status = "ok"
        device.reported_ips_received_at = timezone.now()
        device.observed_ip = "192.0.2.20"
        device.observed_ip_received_at = timezone.now()
        device.reported_agent_version = "0.2.0"
        device.last_heartbeat_at = timezone.now()
        device.save()
        snapshot = Device.objects.values().get(pk=device.pk)
        release = RunnerRelease.objects.create()
        now = timezone.now()
        job = Job.objects.create(device=device, release=release, not_before=now, expires_at=now,
            collection_start=now, collection_end=now, execution_state="succeeded", collection_state="evaluated",
            report={"evidence_ids": ["synthetic-evidence-1"]})
        code_before = PairingCode.objects.values().get()
        job_before = Job.objects.values().get(pk=job.pk)
        archive_device(actor=self.admin, device_id=device.pk)
        after = Device.objects.values().get(pk=device.pk)
        for field in set(snapshot) - {"revoked", "archived_at", "archived_by_id"}:
            self.assertEqual(after[field], snapshot[field], field)
        self.assertEqual(PairingCode.objects.values().get(), code_before)
        self.assertEqual(Job.objects.values().get(pk=job.pk), job_before)

    def test_archived_heartbeat_denies_even_if_loaded_revocation_is_inconsistent(self):
        from devices.archive import archive_device
        enrolled = self.enrolled()
        device = Device.objects.get()
        archive_device(actor=self.admin, device_id=device.pk)
        headers = {"HTTP_X_FORWARDED_PROTO": "https", "HTTP_X_AEGIS_CLIENT_VERIFY": "SUCCESS",
                   "HTTP_X_AEGIS_CLIENT_CERT": quote(enrolled["certificate_pem"], safe="")}
        # Simulate inconsistent legacy storage at the ORM materialization
        # boundary. The real DB constraint remains enabled and unchanged.
        with patch.object(Device, "revoked", new_callable=PropertyMock, return_value=False):
            response = self.client.post("/agent/v2/heartbeat",
                {"protocol": "2.0", "device_id": str(device.pk), "generation": 1},
                content_type="application/json", **headers)
        self.assertEqual(response.status_code, 403)
        device.refresh_from_db()
        self.assertIsNone(device.last_heartbeat_at)

    def test_invalid_uuid_empty_body_and_wrong_methods_are_closed(self):
        client = self.login_human(self.admin)
        device = Device.objects.create(environment_id="synthetic", certificate_sha256="a"*64, connection_kind="paired_presence")
        route = f"/api/v2/devices/{device.pk}/archive"
        self.assertEqual(client.get(route).status_code, 405)
        self.assertEqual(self.human_post(client, route, "").status_code, 400)
        self.assertEqual(self.human_post(client, "/api/v2/devices/not-a-uuid/archive", {}).status_code, 400)
        self.assertEqual(client.get("/api/v2/devices/not-a-uuid").status_code, 400)
        self.assertEqual(client.get(f"/api/v2/devices/{uuid.uuid4()}").status_code, 404)

    def test_stale_admin_form_cannot_restore_archive_or_overwrite_snapshot(self):
        from devices.archive import archive_device
        enrolled = self.enrolled()
        device = Device.objects.get(pk=enrolled["device_id"])
        stale = Device.objects.get(pk=device.pk)
        self.assertIsNone(stale.last_heartbeat_at)
        heartbeat = self.client.post("/agent/v2/heartbeat",
            {"protocol": "2.0", "device_id": str(device.pk), "generation": 1},
            content_type="application/json", HTTP_X_FORWARDED_PROTO="https",
            HTTP_X_AEGIS_CLIENT_VERIFY="SUCCESS",
            HTTP_X_AEGIS_CLIENT_CERT=quote(enrolled["certificate_pem"], safe=""))
        self.assertEqual(heartbeat.status_code, 200)
        final_heartbeat = Device.objects.get(pk=device.pk).last_heartbeat_at
        self.assertIsNotNone(final_heartbeat)
        Device.objects.filter(pk=device.pk).update(reported_ips=["192.0.2.10"], ip_collection_status="ok")
        archive_device(actor=self.admin, device_id=device.pk)
        expected = Device.objects.values().get(pk=device.pk)
        stale.hostname = "synthetic edited label"
        request=RequestFactory().post('/')
        request.user=self.owner
        DeviceAdmin(Device, AdminSite()).save_model(request, stale, None, True)
        device.refresh_from_db()
        self.assertEqual(device.last_heartbeat_at, final_heartbeat)
        self.assertEqual(device.archived_at, expected["archived_at"])
        self.assertEqual(device.archived_by_id, expected["archived_by_id"])
        self.assertTrue(device.revoked)
        self.assertEqual(device.reported_ips, ["192.0.2.10"])
        self.assertEqual(device.ip_collection_status, "ok")
