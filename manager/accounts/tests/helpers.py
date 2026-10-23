from time import time
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import Client, TestCase


class AccountsCase(TestCase):
    def login_human(self, user, password="synthetic-test-password"):
        client = Client(enforce_csrf_checks=True)
        bootstrap = client.get("/api/v1/auth/session")
        self.assertEqual(bootstrap.status_code, 200)
        self.login_epoch = int(time())
        with patch("accounts.sessions.time", return_value=self.login_epoch):
            response = client.post("/api/v1/auth/login", {"username": user.username, "password": password},
                                   content_type="application/json", HTTP_X_CSRFTOKEN=bootstrap.json()["csrf_token"])
        self.assertEqual(response.status_code, 200)
        return client

    def human_post(self, client, route, body):
        token = client.get("/api/v1/auth/session").json()["csrf_token"]
        return client.post(route, body, content_type="application/json", HTTP_X_CSRFTOKEN=token)

    @classmethod
    def setUpTestData(cls):
        users = get_user_model().objects
        cls.owner = users.create_superuser("owner", password="synthetic-test-password")
        for role, name in (("admin", "AEGIS Administrators"), ("operator", "AEGIS Operators"), ("viewer", "AEGIS Viewers")):
            user = users.create_user(role, password="synthetic-test-password")
            user.groups.add(Group.objects.get(name=name))
            setattr(cls, role, user)
