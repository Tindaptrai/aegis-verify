from typing import TYPE_CHECKING

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db.models import Q

if TYPE_CHECKING:
    from django.contrib.auth.models import User


CAPABILITIES = (
    "view", "run_jobs", "import_scenarios", "publish_scenarios",
    "manage_devices", "manage_connections", "export_evidence", "manage_users",
)
PRESETS = {
    "admin": frozenset(CAPABILITIES),
    "operator": frozenset({"view", "run_jobs", "export_evidence"}),
    "viewer": frozenset({"view"}),
}
PRESET_GROUP_NAMES = {
    "admin": "AEGIS Administrators",
    "operator": "AEGIS Operators",
    "viewer": "AEGIS Viewers",
}


def _fresh_active_user(actor):
    if not getattr(actor, "is_authenticated", False) or getattr(actor, "pk", None) is None:
        return None
    return get_user_model().objects.filter(pk=actor.pk, is_active=True).first()


def _effective_permissions(user):
    if user.is_superuser:
        return frozenset(CAPABILITIES)
    capabilities = frozenset(Permission.objects.filter(
        Q(user=user) | Q(group__user=user),
        content_type__app_label="accounts", content_type__model="accountsecurity",
        codename__in=CAPABILITIES,
    ).values_list("codename", flat=True))
    return capabilities if "view" in capabilities else frozenset()


def effective_product_permissions(actor) -> frozenset[str]:
    user = _fresh_active_user(actor)
    return _effective_permissions(user) if user is not None else frozenset()


def external_group_capabilities(user) -> frozenset[str]:
    user = _fresh_active_user(user)
    if user is None:
        return frozenset()
    return frozenset(Permission.objects.filter(
        group__in=user.groups.exclude(name__in=PRESET_GROUP_NAMES.values()),
        content_type__app_label="accounts", content_type__model="accountsecurity",
        codename__in=CAPABILITIES,
    ).values_list("codename", flat=True))


def require_product_permission(actor, codename: str) -> "User":
    user = _fresh_active_user(actor)
    if user is None or codename not in CAPABILITIES or codename not in _effective_permissions(user):
        raise PermissionError("permission_denied")
    return user


def require_product_admin(actor) -> "User":
    user = _fresh_active_user(actor)
    if user is None or _effective_permissions(user) != PRESETS["admin"]:
        raise PermissionError("permission_denied")
    return user
