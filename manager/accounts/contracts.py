"""Bounded human API input and read-only account presentation."""
import json

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import RequestDataTooBig
from django.db.models import Q
from django.middleware.csrf import get_token

from .errors import AccountError
from .models import AccountSecurity
from .permissions import CAPABILITIES, PRESETS, PRESET_GROUP_NAMES, effective_product_permissions


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def _invalid_constant(value):
    raise ValueError


def parse_json(request) -> dict:
    try:
        if request.content_type != "application/json" or len(request.body) > 16384:
            raise ValueError
        data = json.loads(request.body.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if type(data) is not dict:
            raise ValueError
        return data
    except (ValueError, UnicodeError, RecursionError, RequestDataTooBig):
        raise AccountError("invalid_request", 400) from None


def user_dto(user, actor) -> dict:
    # Assigned authority is presented even for a locked target. Authorization
    # still uses the active-only permission helpers and a fresh actor lookup.
    user = get_user_model().objects.get(pk=user.pk)
    product = Permission.objects.filter(content_type__app_label="accounts", content_type__model="accountsecurity", codename__in=CAPABILITIES)
    assigned = (frozenset(CAPABILITIES) if user.is_superuser else frozenset(
        product.filter(Q(user=user) | Q(group__user=user)).values_list("codename", flat=True)
    ))
    inherited = frozenset(product.filter(
        group__in=user.groups.exclude(name__in=PRESET_GROUP_NAMES.values())
    ).values_list("codename", flat=True))
    technical = user.is_staff or user.is_superuser
    role = "technical" if technical else next((key for key, grants in PRESETS.items() if assigned == grants), "custom")
    display_name = AccountSecurity.objects.filter(user_id=user.pk).values_list("display_name", flat=True).first()
    return {
        "id": user.pk, "username": user.username, "display_name": display_name or "",
        "is_active": user.is_active, "role": role,
        "capabilities": [key for key in CAPABILITIES if key in assigned],
        "inherited_capabilities": [key for key in CAPABILITIES if key in inherited],
        "editable": not technical and "manage_users" in effective_product_permissions(actor),
    }


def session_dto(request) -> dict:
    authenticated = bool(request.user.is_authenticated and request.user.is_active)
    return {
        "authenticated": authenticated, "csrf_token": get_token(request),
        "user": user_dto(request.user, request.user) if authenticated else None,
        "expires_at": request.session.get("aegis_deadline") if authenticated else None,
    }
