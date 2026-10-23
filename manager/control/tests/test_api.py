import base64
import hashlib
import json
import tempfile
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from control.models import Device, RunnerRelease, Job, AuditEntry
from control.jobs import approve_job, reconcile_job


class ProtocolTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        now = timezone.now()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-agent")])
        cls.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(cls.key.public_key()).serial_number(1)
                    .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                    .sign(cls.key, hashes.SHA256()))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key_path = Path(self.tmp.name) / "signing.pem"
        key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        self.settings_override = override_settings(MANAGER_SIGNING_KEY=str(key_path))
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        self.owner = get_user_model().objects.create_superuser("owner", "", "synthetic")
        self.device = Device.objects.create(environment_id="lab", certificate_sha256=self.cert.fingerprint(hashes.SHA256()).hex(), wazuh_agent_id="synthetic")
        scenario = Path(self.tmp.name) / "scenario.yaml"
        profile = Path(self.tmp.name) / "profile.json"
        scenario.write_bytes(b"synthetic scenario")
        profile.write_bytes(b"synthetic profile")
        self.release = RunnerRelease.objects.create(scenario_path=str(scenario), profile_path=str(profile), scenario_sha256=hashlib.sha256(scenario.read_bytes()).hexdigest(), profile_sha256=hashlib.sha256(profile.read_bytes()).hexdigest(), runner_sha256="a"*64, kit_sha256="b"*64, payload_sha256="c"*64, rule_hashes={"baseline": "d"*64, "behavioral": "e"*64})
        self.now = timezone.now().replace(microsecond=0)
        self.headers = {"REMOTE_ADDR": "127.0.0.1", "HTTP_X_FORWARDED_PROTO": "https", "HTTP_X_AEGIS_CLIENT_VERIFY": "SUCCESS", "HTTP_X_AEGIS_CLIENT_CERT": quote(self.cert.public_bytes(serialization.Encoding.PEM).decode(), safe="")}

    def job(self):
        return Job.objects.create(device=self.device, release=self.release, not_before=self.now-timedelta(seconds=1), expires_at=self.now+timedelta(seconds=120), collection_start=self.now-timedelta(seconds=10), collection_end=self.now+timedelta(seconds=430), parameters={"run_label":"A", "rule_revision":"baseline", "rule_sha256":"d"*64})

    def post(self, route="poll", body=None, **headers):
        return self.client.post("/agent/v1/"+route, json.dumps(body or {"protocol":"0.1.0"}), content_type="application/json", **(self.headers | headers))

    def claim(self):
        job=self.job()
        approve_job(job.id, self.owner)
        response=self.post()
        self.assertEqual(response.status_code,200)
        job.refresh_from_db()
        return job,response.json()

    def receipt(self, job):
        return {"protocol":"0.1.0", "receipt_id":"11111111-1111-4111-8111-111111111111", "job_id":str(job.id), "payload_sha256":job.payload_sha256, "state":"succeeded", "started_at":self.now.strftime("%Y-%m-%dT%H:%M:%SZ"), "finished_at":(self.now+timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), "exit_code":0, "cleanup_succeeded":True}

    def test_draft_never_dispatches(self):
        self.job()
        self.assertEqual(self.post().status_code,204)

    def test_paired_presence_cannot_be_approved_even_with_manual_mapping(self):
        self.device.connection_kind = "paired_presence"
        self.device.save(update_fields=["connection_kind"])
        job = self.job()
        with self.assertRaisesMessage(ValueError, "Device unavailable"):
            approve_job(job.pk, self.owner)
        job.refresh_from_db()
        self.assertEqual(job.execution_state, "draft")
        self.assertIsNone(job.envelope)

    def test_approval_requires_owner(self):
        job=self.job()
        outsider=get_user_model().objects.create_user("viewer")
        with self.assertRaises(PermissionError): approve_job(job.id,outsider)
        self.assertEqual(self.client.get("/admin/control/job/").status_code,302)
        self.client.force_login(self.owner)
        self.assertEqual(self.client.get("/admin/control/job/").status_code,200)

    def test_exact_signed_bytes_and_duplicate_poll(self):
        job,envelope=self.claim()
        payload=base64.b64decode(envelope["payload"])
        self.key.public_key().verify(base64.b64decode(envelope["signature"]),payload,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
        self.assertEqual(hashlib.sha256(payload).hexdigest(),job.payload_sha256)
        self.assertEqual(json.loads(payload)["run_id"],str(job.id))
        self.assertEqual(self.post().json(),envelope)

    def test_operator_approval_uses_fresh_authority_after_cached_grants_revoked(self):
        from django.contrib.auth.models import Group
        actor = get_user_model().objects.create_user('synthetic-operator')
        actor.groups.add(Group.objects.get(name='AEGIS Operators'))
        actor.get_all_permissions()
        job = self.job()
        approve_job(job.pk, actor)
        job.refresh_from_db()
        self.assertEqual(job.execution_state, 'queued')
        reconcile_job(job.pk, self.owner)
        actor.groups.clear()
        newer = self.job()
        with self.assertRaises(PermissionError):
            approve_job(newer.pk, actor)
        newer.refresh_from_db()
        self.assertEqual(newer.execution_state, 'draft')

    def test_product_job_action_matrix_preserves_reconcile_and_admin_boundaries(self):
        from django.contrib import admin
        from django.contrib.auth.models import Group, Permission
        from django.test import RequestFactory
        from control.admin import OwnerAdmin
        from control.jobs import cancel_job
        for role, allowed, reconcile in (('Viewer', False, False), ('Operator', True, False), ('Administrator', True, True)):
            actor = get_user_model().objects.create_user('synthetic-' + role)
            actor.groups.add(Group.objects.get(name={'Viewer': 'AEGIS Viewers', 'Operator': 'AEGIS Operators', 'Administrator': 'AEGIS Administrators'}[role]))
            job = self.job()
            if allowed:
                approve_job(job.pk, actor)
                job.refresh_from_db()
                self.assertEqual(job.execution_state, 'queued')
                if reconcile:
                    reconcile_job(job.pk, actor)
                else:
                    with self.assertRaises(PermissionError): reconcile_job(job.pk, actor)
                    cancel_job(job.pk, actor)
                    job.refresh_from_db()
                    self.assertEqual(job.execution_state, 'cancelled')
                    self.assertTrue(AuditEntry.objects.filter(job=job, action='cancelled', actor=str(actor.pk)).exists())
            else:
                with self.assertRaises(PermissionError): approve_job(job.pk, actor)
                with self.assertRaises(PermissionError): cancel_job(job.pk, actor)
            request = RequestFactory().get('/admin/')
            request.user = actor
            self.assertFalse(OwnerAdmin(Job, admin.site).has_module_permission(request))
        manager = get_user_model().objects.create_user('synthetic-account-manager')
        manager.user_permissions.add(*Permission.objects.filter(content_type__app_label='accounts', codename__in=('view', 'manage_users')))
        job = self.job()
        approve_job(job.pk, self.owner)
        with self.assertRaises(PermissionError): reconcile_job(job.pk, manager)
        reconcile_job(job.pk, self.owner)
        get_user_model().objects.filter(pk=self.owner.pk).update(is_active=False)
        with self.assertRaises(PermissionError): cancel_job(self.job().pk, self.owner)

    def test_untrusted_proxy_revoked_wrong_certificate_denied(self):
        self.assertEqual(self.post(REMOTE_ADDR="192.0.2.1").status_code,403)
        self.assertEqual(self.post(HTTP_X_FORWARDED_PROTO="http").status_code,403)
        self.device.revoked=True; self.device.save()
        self.assertEqual(self.post().status_code,403)
        self.device.revoked=False; self.device.certificate_sha256="0"*64; self.device.save()
        self.assertEqual(self.post().status_code,403)

    def test_expired_lease_cannot_start(self):
        job,_=self.claim()
        Job.objects.filter(pk=job.pk).update(expires_at=self.now-timedelta(seconds=1))
        self.assertEqual(self.post(f"jobs/{job.id}/start", {"protocol":"0.1.0", "payload_sha256":job.payload_sha256}).status_code,409)

    def test_start_once_receipt_retry_conflict_and_collection_singleflight(self):
        job,_=self.claim()
        start={"protocol":"0.1.0", "payload_sha256":job.payload_sha256}
        self.assertEqual(self.post(f"jobs/{job.id}/start",start).status_code,200)
        self.assertEqual(self.post(f"jobs/{job.id}/start",start).status_code,409)
        self.assertEqual(self.post().status_code,204)
        receipt=self.receipt(job)
        route=f"jobs/{job.id}/receipt"
        self.assertEqual(self.post(route,receipt).status_code,200)
        self.assertEqual(self.post(route,receipt).status_code,200)
        self.assertEqual(self.post(route,receipt|{"exit_code":1,"state":"failed"}).status_code,409)
        next_job=self.job()
        with self.assertRaises(ValueError): approve_job(next_job.id,self.owner)
        reconcile_job(job.id,self.owner)
        approve_job(next_job.id,self.owner)
        self.assertEqual(self.post().status_code,200)

    def test_unexpected_duplicate_and_oversized_fields_rejected(self):
        self.assertEqual(self.post(body={"protocol":"0.1.0", "shell":"bad"}).status_code,400)
        for body in ['{"protocol":"0.1.0","protocol":"0.1.0"}', ' '*65537]:
            response=self.client.post("/agent/v1/poll",body,content_type="application/json",**self.headers)
            self.assertEqual(response.status_code,400)

    def test_receipt_bounds_and_cross_device(self):
        job,_=self.claim()
        self.post(f"jobs/{job.id}/start",{"protocol":"0.1.0","payload_sha256":job.payload_sha256})
        receipt=self.receipt(job)
        self.assertEqual(self.post(f"jobs/{job.id}/receipt",receipt|{"started_at":"2000-01-01T00:00:00Z"}).status_code,400)
        self.device.generation += 1; self.device.save()
        self.assertEqual(self.post(f"jobs/{job.id}/receipt",receipt).status_code,403)

    def test_release_pin_change_and_unknown_never_dispatch_again(self):
        job=self.job()
        Path(self.release.scenario_path).write_bytes(b"changed")
        with self.assertRaises(ValueError): approve_job(job.id,self.owner)

    def test_audit_cannot_be_changed_or_deleted(self):
        job,_=self.claim()
        entry=AuditEntry.objects.filter(job=job).first()
        entry.action="altered"
        with self.assertRaises(ValueError): entry.save()
        with self.assertRaises(ValueError): entry.delete()

    def test_approval_snapshots_mapping_and_bindings(self):
        self.release.evaluation_bindings=[{"name":"endpoint", "value":"synthetic-host"}]
        self.release.save()
        job,_=self.claim()
        self.device.wazuh_agent_id="changed"; self.device.save()
        self.assertEqual(job.approved_wazuh_agent_id,"synthetic")
        self.assertEqual(job.evaluation_bindings,[{"name":"endpoint", "value":"synthetic-host"}])

    def test_cancel_queued_is_owner_audited_and_never_claimed(self):
        from control.jobs import cancel_job
        job,_=self.claim()
        cancel_job(job.id,self.owner)
        self.assertEqual(self.post().status_code,204)
        job.refresh_from_db()
        self.assertEqual(job.execution_state,"cancelled")
        self.assertTrue(AuditEntry.objects.filter(job=job,action="cancelled").exists())

    def test_reconciled_lease_cannot_be_started(self):
        job,_=self.claim()
        reconcile_job(job.id,self.owner)
        self.assertEqual(self.post(f"jobs/{job.id}/start",{"protocol":"0.1.0","payload_sha256":job.payload_sha256}).status_code,409)

    def test_owner_reconciliation_cannot_release_running_collection(self):
        job,_=self.claim()
        Job.objects.filter(pk=job.pk).update(collection_state="collecting")
        with self.assertRaises(ValueError): reconcile_job(job.pk,self.owner)

    def test_lost_start_response_unknown_receipt_without_observed_launch(self):
        job,_=self.claim()
        self.post(f"jobs/{job.id}/start",{"protocol":"0.1.0","payload_sha256":job.payload_sha256})
        receipt=self.receipt(job) | {"state":"execution_unknown", "started_at":None, "finished_at":self.now.strftime("%Y-%m-%dT%H:%M:%SZ"), "exit_code":None, "cleanup_succeeded":False}
        Job.objects.filter(pk=job.pk).update(expires_at=self.now-timedelta(seconds=600))
        self.assertEqual(self.post(f"jobs/{job.id}/receipt",receipt).status_code,200)
        self.assertEqual(self.post().status_code,204)

    def test_receipt_deadline_uses_signed_timeout_not_mutated_release(self):
        job,_=self.claim()
        self.post(f"jobs/{job.id}/start",{"protocol":"0.1.0","payload_sha256":job.payload_sha256})
        self.release.timeout_seconds=9999; self.release.save()
        receipt=self.receipt(job) | {"finished_at":(self.now+timedelta(seconds=350)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        self.assertEqual(self.post(f"jobs/{job.id}/receipt",receipt).status_code,400)

    def test_admin_does_not_edit_signed_job_fields(self):
        job,_=self.claim()
        self.client.force_login(self.owner)
        response=self.client.post(f"/admin/control/job/{job.id}/change/",{"execution_state":"draft", "payload_sha256":"0"*64, "_save":"Save"})
        self.assertIn(response.status_code,(200,302))
        job.refresh_from_db()
        self.assertEqual(job.execution_state,"leased")
        self.assertNotEqual(job.payload_sha256,"0"*64)

    def test_failed_collection_requires_owner_reconciliation(self):
        job,_=self.claim()
        Job.objects.filter(pk=job.pk).update(execution_state="succeeded",collection_state="failed")
        next_job=self.job()
        with self.assertRaises(ValueError): approve_job(next_job.pk,self.owner)

    def unknown_receipt(self, job):
        return self.receipt(job) | {"state":"execution_unknown", "started_at":None, "finished_at":self.now.strftime("%Y-%m-%dT%H:%M:%SZ"), "exit_code":None, "cleanup_succeeded":False}

    def test_start_request_never_received_unknown_receipt_is_accepted(self):
        job,_=self.claim()
        route=f"jobs/{job.id}/receipt"
        receipt=self.unknown_receipt(job)
        self.assertEqual(self.post(route,receipt).status_code,200)
        self.assertEqual(self.post(route,receipt).status_code,200)
        job.refresh_from_db()
        self.assertEqual(job.execution_state,"execution_unknown")
        self.assertEqual(self.post().status_code,204)
        with self.assertRaises(ValueError): approve_job(self.job().pk,self.owner)
        self.assertEqual(self.post(route,self.receipt(job)).status_code,409)

    def test_late_unknown_after_reconciliation_does_not_affect_new_job(self):
        job,_=self.claim()
        reconcile_job(job.pk,self.owner)
        newer=self.job(); approve_job(newer.pk,self.owner)
        self.assertEqual(self.post(f"jobs/{job.id}/receipt",self.unknown_receipt(job)).status_code,200)
        job.refresh_from_db(); newer.refresh_from_db()
        self.assertEqual(job.collection_state,"reconciled")
        self.assertEqual(job.execution_state,"execution_unknown")
        self.assertEqual(newer.execution_state,"queued")
        self.assertEqual(self.post(f"jobs/{job.id}/receipt",self.unknown_receipt(job)).status_code,200)
        self.assertEqual(self.post(f"jobs/{job.id}/receipt",self.unknown_receipt(job)|{"receipt_id":"22222222-2222-4222-8222-222222222222"}).status_code,409)
        self.assertEqual(self.post().status_code,200)

    def test_cancelled_or_expired_lease_unknown_preserves_terminal_state(self):
        from control.jobs import cancel_job
        for state in ("cancelled", "expired"):
            with self.subTest(state=state):
                job,_=self.claim()
                if state == "cancelled": cancel_job(job.pk,self.owner)
                else: Job.objects.filter(pk=job.pk).update(execution_state="expired")
                self.assertEqual(self.post(f"jobs/{job.id}/receipt",self.unknown_receipt(job)).status_code,200)
                job.refresh_from_db()
                self.assertEqual(job.execution_state,state)
                self.assertEqual(job.receipt["state"],"execution_unknown")

    def test_unknown_receipt_for_approved_but_never_leased_job_denied(self):
        job=self.job(); approve_job(job.pk,self.owner)
        job.refresh_from_db()
        self.assertEqual(self.post(f"jobs/{job.id}/receipt",self.unknown_receipt(job)).status_code,409)

    def test_cancelled_queued_job_cannot_acknowledge_unknown_receipt(self):
        from control.jobs import cancel_job
        job=self.job(); approve_job(job.pk,self.owner)
        cancel_job(job.pk,self.owner)
        job.refresh_from_db()
        self.assertEqual(self.post(f"jobs/{job.id}/receipt",self.unknown_receipt(job)).status_code,409)

    def test_admin_reconcile_active_collection_reports_error(self):
        job,_=self.claim()
        Job.objects.filter(pk=job.pk).update(collection_state="collecting")
        self.client.force_login(self.owner)
        response=self.client.post("/admin/control/job/", {"action":"reconcile", "_selected_action":[str(job.pk)], "index":"0"}, follow=True)
        self.assertEqual(response.status_code,200)
        self.assertContains(response,"Cannot reconcile draft or active collection")
        job.refresh_from_db()
        self.assertEqual(job.collection_state,"collecting")
