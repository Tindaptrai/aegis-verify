import io
import uuid
from django.test import Client, RequestFactory
from .helpers import PairingCase, component


class ApiTests(PairingCase):
    def test_human_permission_csrf_no_store_and_closed_input(self):
        component(self, "views")
        viewer = self.login_human(self.viewer)
        self.assertEqual(self.human_post(viewer, "/api/v1/pairing-codes", {"environment_id": "synthetic"}).status_code, 403)
        admin = self.login_human(self.admin)
        self.assertEqual(admin.post("/api/v1/pairing-codes", {"environment_id": "synthetic"}, content_type="application/json").status_code, 403)
        for data in ({"environment_id": "bad env"}, {"environment_id": ""}, {"environment_id": "-bad"},
                     {"environment_id": "synthetic", "extra": True}, {"environment_id": 1}):
            response = self.human_post(admin, "/api/v1/pairing-codes", data)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json(), {"error": {"code": "invalid_request"}})
            self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(self.client.get("/agent/v2/enroll").status_code, 405)
        self.assertEqual(self.client.post("/agent/v2/enroll/", {}, content_type="application/json").status_code, 404)

    def test_machine_json_duplicates_unknown_values_types_and_body_limit(self):
        component(self, "views")
        data = self.enrollment()
        for change in ({"os": "macos"}, {"architecture": "arm64"}, {"agent_version": "9.0"},
                       {"hostname": "a\nb"}, {"hostname": ""}, {"hostname": "x" * 256},
                       {"csr_pem": "x" * 8193}, {"csr_pem": "é"}, {"protocol": 2},
                       {"pairing_code": "A" * 64}, {"extra": True}):
            with self.subTest(change=change):
                response = self.client.post("/agent/v2/enroll", data | change, content_type="application/json", secure=True)
                self.assertEqual(response.status_code, 400)
        for raw in ('{"protocol":"2.0","protocol":"2.0"}', '{"value":NaN}', '[]', '"string"', '{', ' ' * 16385):
            self.assertEqual(self.client.post("/agent/v2/enroll", raw, content_type="application/json", secure=True).status_code, 400)
        self.assertEqual(self.client.post("/agent/v2/enroll", data, content_type="application/json").status_code, 403)

    def test_runtime_cap_reads_only_limit_plus_one_without_content_length(self):
        views = component(self, "views")
        request = RequestFactory().post("/agent/v2/enroll", "{}", content_type="application/json", secure=True)
        request.META.pop("CONTENT_LENGTH", None)
        stream = io.BytesIO(b" " * 20000)
        request._stream = stream
        response = views.enroll(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(stream.tell(), 16385)

    def test_machine_enrollment_success_and_issuer_unavailable_have_fixed_closed_dto(self):
        component(self, "views")
        data = self.enrollment()
        unavailable = self.client.post("/agent/v2/enroll", data, content_type="application/json", secure=True)
        self.assertEqual((unavailable.status_code, unavailable.json()), (503, {"error": {"code": "issuer_unavailable"}}))
        self.initialize()
        response = Client(enforce_csrf_checks=True).post("/agent/v2/enroll", data, content_type="application/json", secure=True)
        self.assertEqual(response.status_code, 201)
        self.assertNotIn(data["pairing_code"], response.content.decode())
        self.assertNotIn("PRIVATE", response.content.decode())
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_listing_uses_view_stable_order_nulls_search_and_no_secrets(self):
        component(self, "views")
        from control.models import Device
        for index in range(52):
            Device.objects.create(id=uuid.UUID(int=index + 1), environment_id="synthetic", certificate_sha256=f"{index:064x}",
                                  hostname=f"host-{index}")
        viewer = self.login_human(self.viewer)
        result = viewer.get("/api/v1/devices").json()
        self.assertEqual((result["count"], result["page"], result["page_size"], len(result["results"])), (52, 1, 50, 50))
        self.assertEqual(result["results"][0], {"id": str(uuid.UUID(int=1)), "hostname": "host-0", "environment_id": "synthetic",
            "wazuh_agent_id": None, "connection_kind": "legacy_v1", "os": None, "architecture": None,
            "agent_version": None, "generation": 1, "status": "unknown", "last_heartbeat_at": None,
            "certificate_expires_at": None, "execution_supported": False})
        page = viewer.get("/api/v1/devices?page=2").json()
        self.assertEqual(len(page["results"]), 2)
        self.assertEqual(viewer.get("/api/v1/devices?search=host-51").json()["count"], 1)
        for query in ("page=0", "page=true", "page=1&page=2", "unknown=x", "search=" + "x" * 101):
            self.assertEqual(viewer.get("/api/v1/devices?" + query).status_code, 400)

    def test_revoke_only_paired_device_and_missing_resources_are_fixed_errors(self):
        services = component(self, "services")
        from control.models import Device
        device = Device.objects.create(environment_id="synthetic", certificate_sha256="a" * 64)
        admin = self.login_human(self.admin)
        response = self.human_post(admin, f"/api/v1/devices/{device.pk}/revoke", {})
        self.assertEqual((response.status_code, response.json()), (409, {"error": {"code": "device_conflict"}}))
        self.assertEqual(self.human_post(admin, f"/api/v1/devices/{uuid.uuid4()}/revoke", {}).status_code, 400)
        self.assertEqual(self.human_post(admin, f"/api/v1/pairing-codes/{uuid.uuid4()}/revoke", {}).status_code, 400)
        Device.objects.filter(pk=device.pk).update(connection_kind="paired_presence")
        self.assertEqual(self.human_post(admin, f"/api/v1/devices/{device.pk}/revoke", {}).status_code, 204)
        device.refresh_from_db()
        self.assertTrue(device.revoked)
