from datetime import timedelta
from urllib.parse import quote

from django.test import RequestFactory
from django.utils import timezone

from control.models import Device
from .helpers import PairingCase, component


class PresenceTests(PairingCase):
    def test_presence_boundaries_precedence_and_legacy_unknown(self):
        contracts = component(self, "contracts")
        now = timezone.now()
        device = Device(connection_kind="paired_presence", certificate_not_before=now - timedelta(days=1),
                        certificate_expires_at=now + timedelta(days=1))
        for age, expected in ((None, "offline"), (-1, "offline"), (0, "online"), (59.999, "online"), (60, "offline")):
            device.last_heartbeat_at = None if age is None else now - timedelta(seconds=age)
            self.assertEqual(contracts.device_status(device, now=now), expected)
        device.certificate_expires_at = now
        self.assertEqual(contracts.device_status(device, now=now), "expired")
        device.revoked = True
        self.assertEqual(contracts.device_status(device, now=now), "revoked")
        device.connection_kind = "legacy_v1"
        self.assertEqual(contracts.device_status(device, now=now), "revoked")
        device.revoked = False
        self.assertEqual(contracts.device_status(device, now=now), "expired")
        device.certificate_expires_at = None
        self.assertEqual(contracts.device_status(device, now=now), "unknown")
        self.assertIsNone(contracts.device_dto(device, now=now)["certificate_expires_at"])

    def test_heartbeat_uses_verified_fingerprint_uuid_generation_and_server_time(self):
        self.initialize()
        services = component(self, "services")
        enrolled = services.enroll_device(self.enrollment())
        body = {"protocol": "2.0", "device_id": enrolled["device_id"], "generation": 1}
        headers = {"HTTP_X_FORWARDED_PROTO": "https", "HTTP_X_AEGIS_CLIENT_VERIFY": "SUCCESS",
                   "HTTP_X_AEGIS_CLIENT_CERT": quote(enrolled["certificate_pem"], safe="")}
        before = timezone.now()
        response = self.client.post("/agent/v2/heartbeat", body, content_type="application/json", **headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"protocol", "server_time", "heartbeat_seconds", "offline_after_seconds"})
        device = Device.objects.get(pk=enrolled["device_id"])
        self.assertGreaterEqual(device.last_heartbeat_at, before)
        for changes in ({"generation": 2}, {"generation": True}, {"device_id": "00000000-0000-0000-0000-000000000000"}, {"extra": True}):
            self.assertIn(self.client.post("/agent/v2/heartbeat", body | changes, content_type="application/json", **headers).status_code, (400, 403))
        for spoof in ({"REMOTE_ADDR": "192.0.2.1"}, {"HTTP_X_FORWARDED_PROTO": "http"},
                      {"HTTP_X_AEGIS_CLIENT_VERIFY": "NONE"}, {"HTTP_X_AEGIS_CLIENT_CERT": "bad"}):
            denied = self.client.post("/agent/v2/heartbeat", body, content_type="application/json", **(headers | spoof))
            self.assertEqual((denied.status_code, denied.json()), (403, {"error": {"code": "identity_denied"}}))
        services.revoke_device(actor=self.admin, device_id=device.pk)
        prior = device.last_heartbeat_at
        self.assertEqual(self.client.post("/agent/v2/heartbeat", body, content_type="application/json", **headers).status_code, 403)
        device.refresh_from_db()
        self.assertEqual(device.last_heartbeat_at, prior)

    def test_v1_identity_and_claim_deny_paired_even_when_mapped(self):
        self.initialize()
        enrolled = component(self, "services").enroll_device(self.enrollment())
        Device.objects.filter(pk=enrolled["device_id"]).update(wazuh_agent_id="manually-mapped")
        request = RequestFactory().post("/agent/v1/poll", HTTP_X_FORWARDED_PROTO="https", HTTP_X_AEGIS_CLIENT_VERIFY="SUCCESS",
                                        HTTP_X_AEGIS_CLIENT_CERT=quote(enrolled["certificate_pem"], safe=""))
        from control.identity import authenticate_device
        from control.jobs import claim_job
        with self.assertRaises(PermissionError):
            authenticate_device(request)
        with self.assertRaises(PermissionError):
            claim_job(Device.objects.get(pk=enrolled["device_id"]))
