"""Absolute, server-enforced human sessions shared by the UI and Django Admin."""
from datetime import datetime, timezone
from time import time

from django.contrib.auth import logout, update_session_auth_hash

from .models import AccountSecurity


def _set_markers(request, generation, deadline):
    request.session["aegis_generation"] = generation
    request.session["aegis_deadline"] = deadline
    request.session.set_expiry(datetime.fromtimestamp(deadline, tz=timezone.utc))


def stamp_login(request, user) -> None:
    security, _ = AccountSecurity.objects.get_or_create(user_id=user.pk)
    _set_markers(request, security.generation, int(time()) + 8 * 60 * 60)


def validate_human_session(request) -> bool:
    generation = request.session.get("aegis_generation")
    deadline = request.session.get("aegis_deadline")
    user = request.user
    valid = (
        user.is_authenticated and user.is_active
        and type(generation) is int and type(deadline) is int
        and deadline > time()
        and AccountSecurity.objects.filter(user_id=user.pk, user__is_active=True, generation=generation).exists()
    )
    if not valid and (user.is_authenticated or "_auth_user_id" in request.session):
        logout(request)
    return bool(valid)


def refresh_own_password_session(request, user, *, original_deadline: int) -> None:
    update_session_auth_hash(request, user)
    generation = AccountSecurity.objects.values_list("generation", flat=True).get(user_id=user.pk)
    _set_markers(request, generation, original_deadline)
