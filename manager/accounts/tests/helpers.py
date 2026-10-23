from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase


class AccountsCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        users = get_user_model().objects
        cls.owner = users.create_superuser("owner", password="synthetic-test-password")
        for role, name in (("admin", "AEGIS Administrators"), ("operator", "AEGIS Operators"), ("viewer", "AEGIS Viewers")):
            user = users.create_user(role, password="synthetic-test-password")
            user.groups.add(Group.objects.get(name=name))
            setattr(cls, role, user)
