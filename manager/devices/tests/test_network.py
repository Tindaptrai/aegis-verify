"""Network claims and proxy observations use synthetic authenticated identities."""
import copy
import json
from urllib.parse import quote

from django.test import SimpleTestCase
from django.utils import timezone

from control.models import Device
from .helpers import PairingCase, component


class NetworkContractTests(SimpleTestCase):
    def test_normalizes_mapped_and_ipv6_literals(self):
        network = component(self, "network")
        for value, expected in (("::ffff:192.0.2.9", "192.0.2.9"), ("2001:0DB8:0:0::9", "2001:db8::9")):
            self.assertEqual(network.normalize_ip(value), expected)

    def test_rejects_nonliteral_or_excluded_addresses(self):
        network = component(self, "network")
        from devices.contracts import DeviceError
        for value in (None, 1, "", " 192.0.2.9", "192.0.2.9 ", "example.test", "https://192.0.2.9", "192.0.2.9:80",
                      "fe80::1%2", "2001:db8::1%eth0", "127.0.0.1", "::1", "0.0.0.0", "::", "224.0.0.1",
                      "ff02::1", "169.254.1.2", "fe80::1", "::ffff:127.0.0.1", "::ffff:169.254.1.2"):
            with self.subTest(value=value), self.assertRaises(DeviceError):
                network.normalize_ip(value)


class NetworkHeartbeatTests(PairingCase):
    def setUp(self):
        super().setUp()
        self.initialize()
        self.enrolled = component(self, "services").enroll_device(self.enrollment())
        self.headers = {"HTTP_X_FORWARDED_PROTO": "https", "HTTP_X_AEGIS_CLIENT_VERIFY": "SUCCESS",
                        "HTTP_X_AEGIS_CLIENT_CERT": quote(self.enrolled["certificate_pem"], safe="")}
        self.body = {"protocol": "2.1", "device_id": self.enrolled["device_id"], "generation": 1,
                     "network": {"collection_status": "ok", "reported_ips": ["2001:0DB8::9", "192.0.2.9", "::ffff:192.0.2.9"],
                                 "truncated": False, "agent_version": "0.2.0"}}

    def post(self, body=None, **headers):
        return self.client.post("/agent/v2/network-heartbeat", self.body if body is None else body,
                                content_type="application/json", **(self.headers | headers))

    def snapshot(self):
        return Device.objects.values().get(pk=self.enrolled["device_id"])

    def test_normalized_snapshot_and_exact_ipv6_inventory_search(self):
        before = timezone.now()
        response = self.post(HTTP_X_AEGIS_PEER_IP="2001:0DB8::8")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"protocol", "server_time", "heartbeat_seconds", "offline_after_seconds"})
        self.assertEqual((response.json()["protocol"], response.json()["heartbeat_seconds"], response.json()["offline_after_seconds"]), ("2.1", 15, 60))
        row = self.snapshot()
        self.assertEqual(row["reported_ips"], ["192.0.2.9", "2001:db8::9"])
        self.assertEqual((row["ip_collection_status"], row["reported_agent_version"], row["observed_ip"]), ("ok", "0.2.0", "2001:db8::8"))
        for name in ("reported_ips_received_at", "observed_ip_received_at", "last_heartbeat_at"):
            self.assertGreaterEqual(row[name], before)
        self.client.force_login(self.admin)
        for search in ("2001:0DB8:0:0:0:0:0:9", "2001:0DB8::8", "::ffff:192.0.2.9"):
            self.assertEqual(self.client.get("/api/v2/devices", {"search": search}).json()["count"], 1)
        self.assertEqual(self.client.get("/api/v2/devices", {"search": "192.0.2.90"}).json()["count"], 0)

    def test_empty_unavailable_and_missing_observation_replace_previous_snapshot(self):
        self.assertEqual(self.post(HTTP_X_AEGIS_PEER_IP="192.0.2.8").status_code, 200)
        for status, ips in (("ok", []), ("unavailable", None)):
            body = copy.deepcopy(self.body)
            body["network"].update(collection_status=status, reported_ips=ips)
            self.assertEqual(self.post(body).status_code, 200)
            row = self.snapshot()
            self.assertEqual((row["ip_collection_status"], row["reported_ips"], row["reported_ips_truncated"]), (status, ips, False))
            self.assertIsNotNone(row["reported_ips_received_at"])
            self.assertIsNone(row["observed_ip"])
            self.assertIsNone(row["observed_ip_received_at"])

    def test_bad_report_or_peer_does_not_refresh_any_device_field(self):
        self.assertEqual(self.post(HTTP_X_AEGIS_PEER_IP="192.0.2.8").status_code, 200)
        previous = self.snapshot()
        invalid = [{"reported_ips": ["2001:db8::9%eth0"]}, {"reported_ips": ["fe80::1"]},
                   {"reported_ips": ["192.0.2.1"] * 33}, {"reported_ips": None}, {"collection_status": "unknown"},
                   {"collection_status": "unavailable"}, {"truncated": True}, {"truncated": 0},
                   {"agent_version": "01.2.0"}, {"agent_version": "0.2.0-preview"}, {"agent_version": "100000.0.0"},
                   {"extra": True}, {"reported_ips": [[[["192.0.2.1"]]]]}]
        for changes in invalid:
            body = copy.deepcopy(self.body)
            body["network"].update(changes)
            with self.subTest(changes=changes):
                self.assertEqual(self.post(body).status_code, 400)
                self.assertEqual(self.snapshot(), previous)
        for peer in ("192.0.2.8,192.0.2.9", "", "192.0.2.8:80", " 192.0.2.8", "2001:db8::8%2"):
            with self.subTest(peer=peer):
                self.assertEqual(self.post(HTTP_X_AEGIS_PEER_IP=peer).status_code, 400)
                self.assertEqual(self.snapshot(), previous)
        for body in (self.body | {"extra": True}, self.body | {"protocol": "2.0"}, self.body | {"generation": True},
                     {k: v for k, v in self.body.items() if k != "network"}):
            self.assertEqual(self.post(body).status_code, 400)
            self.assertEqual(self.snapshot(), previous)
        raw = json.dumps(self.body).replace('"2.1"', '"2.1", "protocol": "2.1"')
        self.assertEqual(self.post(raw).status_code, 400)
        self.assertEqual(self.post(json.dumps(self.body) + " " * 16384).status_code, 400)
        self.assertEqual(self.snapshot(), previous)

    def test_truncated_requires_32_unique_normalized_addresses(self):
        body = copy.deepcopy(self.body)
        body["network"].update(reported_ips=[f"192.0.2.{i}" for i in range(1, 33)], truncated=True)
        self.assertEqual(self.post(body).status_code, 200)
        previous = self.snapshot()
        body["network"]["reported_ips"][-1] = "::ffff:192.0.2.1"
        self.assertEqual(self.post(body).status_code, 400)
        self.assertEqual(self.snapshot(), previous)

    def test_untrusted_identity_cannot_supply_observation(self):
        for change in ({"REMOTE_ADDR": "192.0.2.9"}, {"HTTP_X_FORWARDED_PROTO": "http"},
                       {"HTTP_X_AEGIS_CLIENT_VERIFY": "NONE"}, {"HTTP_X_AEGIS_CLIENT_CERT": "bad"}):
            before = self.snapshot()
            self.assertEqual(self.post(**(change | {"HTTP_X_AEGIS_PEER_IP": "192.0.2.8"})).status_code, 403)
            self.assertEqual(self.snapshot(), before)

    def test_old_heartbeat_clears_claims_but_updates_observation_independently(self):
        for peer in ("192.0.2.8", None):
            self.assertEqual(self.post().status_code, 200)
            old = {k: v for k, v in self.body.items() if k != "network"} | {"protocol": "2.0"}
            headers = self.headers | ({"HTTP_X_AEGIS_PEER_IP": peer} if peer else {})
            response = self.client.post("/agent/v2/heartbeat", old, content_type="application/json", **headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["protocol"], "2.0")
            row = self.snapshot()
            self.assertEqual((row["ip_collection_status"], row["reported_ips_truncated"]), ("unknown", False))
            for name in ("reported_ips", "reported_ips_received_at", "reported_agent_version"):
                self.assertIsNone(row[name])
            self.assertEqual(row["observed_ip"], peer)
            self.assertEqual(row["observed_ip_received_at"] is None, peer is None)
        previous = self.snapshot()
        self.assertEqual(self.client.post("/agent/v2/heartbeat", old, content_type="application/json",
                                         **(self.headers | {"HTTP_X_AEGIS_PEER_IP": "bad"})).status_code, 400)
        self.assertEqual(self.snapshot(), previous)

    def test_revoked_and_archived_devices_reject_network_updates(self):
        for archived in (False, True):
            Device.objects.filter(pk=self.enrolled["device_id"]).update(revoked=True, archived_at=timezone.now() if archived else None)
            before = self.snapshot()
            self.assertEqual(self.post().status_code, 403)
            self.assertEqual(self.snapshot(), before)

    def test_new_enrollment_version_preserves_closed_20_response(self):
        data = self.enrollment() | {"agent_version": "0.2.0"}
        response = self.client.post("/agent/v2/enroll", data, content_type="application/json", HTTP_X_FORWARDED_PROTO="https")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["protocol"], "2.0")
        self.assertEqual(set(response.json()), set(self.enrolled))
        self.assertEqual(Device.objects.get(pk=response.json()["device_id"]).agent_version, "0.2.0")
