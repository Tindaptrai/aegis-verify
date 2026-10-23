from django.apps import AppConfig
from django.contrib.admin.apps import AdminConfig


class GuardedAdminConfig(AdminConfig):
    default_site = "accounts.admin_site.GuardedAdminSite"


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "accounts"

    def ready(self):
        from . import signals  # noqa: F401
