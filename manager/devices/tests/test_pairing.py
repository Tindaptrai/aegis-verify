import hashlib
from datetime import timedelta
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django.contrib.auth.models import Group
from django.utils import timezone

from control.models import Device
from .helpers import PairingCase, component


class PairingTests(PairingCase):
    def test_code_is_digest_only_exactly_600_seconds_and_audit_is_bounded(self):
        mint = self.mint()
        models = component(self, "models")
        code = models.PairingCode.objects.get(pk=mint["id"])
        self.assertEqual(code.code_sha256, hashlib.sha256(mint["code"].encode()).hexdigest())
        self.assertEqual(code.expires_at - code.created_at, timedelta(seconds=600))
        self.assertNotIn(mint["code"], str(code.__dict__))
        self.assertNotIn(mint["code"], str(list(models.EnrollmentAudit.objects.values())))
        audit = models.EnrollmentAudit.objects.first()
        with self.assertRaises(ValueError):
            audit.save()
        with self.assertRaises(ValueError):
            models.EnrollmentAudit.objects.all().update(action="changed")
        with self.assertRaises(ValueError):
            models.EnrollmentAudit.objects.all().delete()

    def test_redemption_creates_presence_identity_and_consumes_code_once(self):
        self.initialize()
        data = self.enrollment()
        services = component(self, "services")
        result = services.enroll_device(data)
        self.assertEqual(set(result), {"protocol", "device_id", "environment_id", "generation", "certificate_pem",
                                      "issuer_pem", "expires_at", "heartbeat_seconds", "offline_after_seconds"})
        self.assertEqual((result["protocol"], result["generation"], result["heartbeat_seconds"], result["offline_after_seconds"]),
                         ("2.0", 1, 15, 60))
        device = Device.objects.get(pk=result["device_id"])
        self.assertEqual(device.connection_kind, "paired_presence")
        self.assertIsNone(device.wazuh_agent_id)
        self.assertIsNone(device.last_heartbeat_at)
        cert = x509.load_pem_x509_certificate(result["certificate_pem"].encode())
        self.assertEqual(device.certificate_sha256, cert.fingerprint(hashes.SHA256()).hex())
        with self.assertRaises(services.DeviceError) as denied:
            services.enroll_device(data)
        self.assertEqual((denied.exception.code, denied.exception.status), ("pairing_denied", 403))
        self.assertEqual(Device.objects.count(), 1)
        audit = str(list(component(self, "models").EnrollmentAudit.objects.values()))
        self.assertNotIn(data["pairing_code"], audit)
        self.assertNotIn("CERTIFICATE REQUEST", audit)

    def test_invalid_expired_revoked_and_demoted_issuer_codes_have_same_denial(self):
        self.initialize()
        services = component(self, "services")
        models = component(self, "models")
        for state in ("unknown", "expired", "revoked", "demoted", "inactive"):
            mint = self.mint()
            if state == "expired":
                models.PairingCode.objects.filter(pk=mint["id"]).update(expires_at=timezone.now())
            if state == "revoked":
                services.revoke_pairing_code(actor=self.admin, code_id=mint["id"])
            if state == "demoted":
                self.admin.groups.clear()
            if state == "inactive":
                type(self.admin).objects.filter(pk=self.admin.pk).update(is_active=False)
            with self.subTest(state=state), self.assertRaises(services.DeviceError) as denied:
                services.enroll_device(self.enrollment(code="0" * 64 if state == "unknown" else mint["code"]))
            self.assertEqual((denied.exception.code, denied.exception.status), ("pairing_denied", 403))
            self.admin.groups.clear()
            self.admin.groups.add(Group.objects.get(name="AEGIS Administrators"))
            type(self.admin).objects.filter(pk=self.admin.pk).update(is_active=True)
        self.assertFalse(Device.objects.exists())

    def test_signing_error_rolls_back_device_consumption_and_audit(self):
        self.initialize()
        data = self.enrollment()
        services, models = component(self, "services"), component(self, "models")
        before = models.EnrollmentAudit.objects.count()
        with patch("devices.issuer.x509.CertificateBuilder.sign", side_effect=ValueError("synthetic signing failure")):
            with self.assertRaises(services.DeviceError) as error:
                services.enroll_device(data)
        self.assertEqual(error.exception.code, "issuer_unavailable")
        self.assertFalse(Device.objects.exists())
        self.assertIsNone(models.PairingCode.objects.get().consumed_device_id)
        self.assertEqual(models.EnrollmentAudit.objects.count(), before)

    def test_missing_issuer_is_lazy_and_does_not_consume_code(self):
        data = self.enrollment()
        services = component(self, "services")
        with self.assertRaises(services.DeviceError) as error:
            services.enroll_device(data)
        self.assertEqual((error.exception.code, error.exception.status), ("issuer_unavailable", 503))
        self.assertIsNone(component(self, "models").PairingCode.objects.get().consumed_device_id)
