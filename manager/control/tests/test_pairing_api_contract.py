"""Public pairing contract, before the devices app exists."""
from accounts.tests.helpers import AccountsCase


class PairingApiContractTests(AccountsCase):
    def test_pairing_mint_returns_one_time_code_and_exact_deadline(self):
        client = self.login_human(self.admin)
        response = self.human_post(client, "/api/v1/pairing-codes", {"environment_id": "synthetic.test"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(set(response.json()), {"id", "code", "environment_id", "expires_at"})
        self.assertRegex(response.json()["code"], r"^[0-9a-f]{64}$")
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_devices_requires_a_human_session(self):
        response = self.client.get("/api/v1/devices")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": {"code": "unauthenticated"}})

    def test_enrollment_rejects_a_non_object_without_csrf(self):
        response = self.client.post("/agent/v2/enroll", "[]", content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": {"code": "invalid_request"}})
