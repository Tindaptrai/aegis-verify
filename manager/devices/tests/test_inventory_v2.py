from django.utils import timezone
from control.models import Device
from devices.contracts import device_dto
from devices.models import EnrollmentAudit
from accounts.tests.helpers import AccountsCase


class InventoryV2Tests(AccountsCase):
    def test_full_metadata_defaults_and_unchanged_v1_shape(self):
        device = Device.objects.create(environment_id="synthetic", certificate_sha256="a"*64, connection_kind="paired_presence")
        client = self.login_human(self.viewer)
        result = client.get("/api/v2/devices")
        self.assertEqual(result.status_code, 200)
        row = result.json()["results"][0]
        old = client.get("/api/v1/devices").json()["results"][0]
        self.assertEqual(old, device_dto(device))
        self.assertEqual(set(row)-set(old), {"reported_ips", "ip_collection_status", "reported_ips_truncated", "reported_ips_received_at", "observed_ip", "observed_ip_received_at", "reported_agent_version", "archived_at", "archived_by_id", "can_archive", "archive_block_reason"})
        self.assertEqual(row["ip_collection_status"], "unknown")
        self.assertFalse(row["reported_ips_truncated"])
        self.assertTrue(row["can_archive"])
        for name in ("reported_ips", "reported_ips_received_at", "observed_ip", "observed_ip_received_at", "reported_agent_version", "archived_at", "archived_by_id", "archive_block_reason"):
            self.assertIsNone(row[name])

    def test_exact_canonical_ip_search_scopes_and_query_validation(self):
        client = self.login_human(self.viewer)
        self.assertEqual(client.get("/api/v2/devices").status_code, 200)
        a = Device.objects.create(environment_id="synthetic", hostname="same", certificate_sha256="a"*64,
            reported_ips=["2001:db8::1"], observed_ip="192.0.2.10", connection_kind="paired_presence")
        b = Device.objects.create(environment_id="synthetic", hostname="same", certificate_sha256="b"*64,
            reported_ips=["2001:db8::1"], connection_kind="paired_presence", revoked=True, archived_at=timezone.now())
        for search in ("2001:0db8:0:0:0:0:0:1", "192.0.2.10", "same"):
            rows = client.get("/api/v2/devices", {"search": search}).json()
            self.assertEqual([r["id"] for r in rows["results"]], [str(a.pk)])
        self.assertEqual(client.get("/api/v2/devices", {"search": "192.0.2.1"}).json()["count"], 0)
        row = client.get("/api/v2/devices", {"scope": "archived"}).json()["results"][0]
        self.assertEqual(row["id"], str(b.pk))
        self.assertEqual((row["can_archive"], row["archive_block_reason"]), (False, "already_archived"))
        for query in ("scope=all", "page=0", "page=1&page=2", "scope=managed&scope=archived", "extra=x"):
            self.assertEqual(client.get("/api/v2/devices?"+query).status_code, 400)
        self.assertEqual(client.get("/api/v1/devices?scope=archived").status_code, 400)

    def test_history_is_closed_paginated_and_view_protected(self):
        device = Device.objects.create(environment_id="synthetic", certificate_sha256="a"*64)
        client = self.login_human(self.viewer)
        route = f"/api/v2/devices/{device.pk}/history"
        self.assertEqual(client.get(route).status_code, 200)
        for _ in range(51):
            EnrollmentAudit.objects.create(action="device_revoked", device_id=device.pk, actor_id=self.admin.pk)
        EnrollmentAudit.objects.create(action="device_revoked")
        result = client.get(route).json()
        self.assertEqual((result["count"], len(result["results"]), result["page_size"]), (51, 50, 50))
        self.assertEqual(set(result["results"][0]), {"action", "created_at", "actor_id", "code_id", "device_id"})
        self.assertEqual(len(client.get(route+"?page=2").json()["results"]), 1)
        self.assertEqual(client.get(route+"?search=foo").status_code, 400)
        self.assertEqual(self.client.get(route).status_code, 401)
        self.viewer.groups.clear()
        self.assertEqual(client.get(route).status_code, 403)
