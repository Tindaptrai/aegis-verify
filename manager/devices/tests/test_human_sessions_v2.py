from accounts.permissions import PRESETS
from accounts.services import update_product_user
from accounts.tests.helpers import AccountsCase
from control.models import Device
from devices.models import EnrollmentAudit


class HumanSessionV2Tests(AccountsCase):
    def invalidate_session(self, client, reason):
        if reason == "revoked_generation":
            fields = dict(actor=self.owner, user_id=self.admin.pk, display_name="",
                          capabilities=sorted(PRESETS["admin"]))
            update_product_user(**fields, active=False)
            update_product_user(**fields, active=True)
            return
        session = client.session
        if reason == "missing_generation":
            del session["aegis_generation"]
        elif reason == "missing_deadline":
            del session["aegis_deadline"]
        else:
            session["aegis_deadline"] = self.login_epoch - 1
        session.save()

    def request_device_route(self, client, device, route):
        if route == "inventory":
            return client.get("/api/v2/devices")
        path = f"/api/v2/devices/{device.pk}"
        if route == "archive":
            # Retain the original valid CSRF token. Refreshing it through v1
            # would validate and flush the stale session before reaching v2.
            return client.post(path + "/archive", {}, content_type="application/json",
                               HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value)
        return client.get(path + ("/history" if route == "history" else ""))

    def test_invalid_sessions_cannot_read_or_archive_devices(self):
        sequence = 0
        for reason in ("revoked_generation", "missing_generation", "missing_deadline", "expired_deadline"):
            for route in ("inventory", "detail", "history", "archive"):
                with self.subTest(reason=reason, route=route):
                    sequence += 1
                    device = Device.objects.create(environment_id="synthetic",
                        certificate_sha256=f"{sequence:064x}", connection_kind="paired_presence")
                    client = self.login_human(self.admin)
                    self.invalidate_session(client, reason)
                    audit_count = EnrollmentAudit.objects.count()
                    response = self.request_device_route(client, device, route)
                    device.refresh_from_db()
                    self.assertEqual((response.status_code, device.revoked, device.archived_at,
                                      EnrollmentAudit.objects.count()), (401, False, None, audit_count))
                    self.assertEqual(response.json()["error"]["code"], "unauthenticated")
                    self.assertEqual(response["Cache-Control"], "no-store")

    def test_fresh_marked_session_can_read_and_archive_devices(self):
        device = Device.objects.create(environment_id="synthetic", certificate_sha256="a" * 64,
                                       connection_kind="paired_presence")
        client = self.login_human(self.admin)
        for route in ("inventory", "detail", "history"):
            with self.subTest(route=route):
                self.assertEqual(self.request_device_route(client, device, route).status_code, 200)
        self.assertEqual(self.request_device_route(client, device, "archive").status_code, 204)
        device.refresh_from_db()
        self.assertTrue(device.revoked)
        self.assertIsNotNone(device.archived_at)
        self.assertEqual(EnrollmentAudit.objects.filter(device_id=device.pk, action="device_archived").count(), 1)
