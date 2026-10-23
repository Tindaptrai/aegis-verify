"""Account writes share one lock, including technical Django Admin writes."""
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.password_validation import MinimumLengthValidator
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import F

from .errors import AccountError
from .models import AccountMutationLock, AccountSecurity, AuthAudit
from .permissions import (
    CAPABILITIES, PRESETS, PRESET_GROUP_NAMES, effective_product_permissions,
    require_product_admin,
)


@contextmanager
def authority_mutation(*, actor):
    """Lock before loading authority; validate the final state before commit.

    Callers perform their authorization, M2M changes, revocation and bounded
    audit inside this context. Bootstrap uses the same first lock directly.
    """
    with transaction.atomic():
        AccountMutationLock.objects.select_for_update().get(pk=1)
        if not get_user_model().objects.filter(pk=getattr(actor, "pk", None), is_active=True).exists():
            raise AccountError("permission_denied", 403)
        yield
        for user in get_user_model().objects.filter(is_active=True).iterator():
            if user.has_usable_password() and (
                user.is_superuser or effective_product_permissions(user) == PRESETS["admin"]
            ):
                break
        else:
            raise AccountError("last_admin", 409)


def validate_product_password(password):
    if type(password) is not str or len(password) > 1024:
        raise AccountError("invalid_password", 400)
    try:
        MinimumLengthValidator(8).validate(password)
    except ValidationError:
        raise AccountError("invalid_password", 400) from None


def _validate_fields(display_name, capabilities, active, extra):
    if extra or type(active) is not bool:
        raise AccountError("invalid_request", 400)
    if type(display_name) is not str or len(display_name) > 150:
        raise AccountError("invalid_display_name", 400)
    if (type(capabilities) not in (tuple, list) or len(capabilities) > len(CAPABILITIES)
            or any(type(item) is not str or item not in CAPABILITIES for item in capabilities)
            or len(set(capabilities)) != len(capabilities)):
        raise AccountError("invalid_capabilities", 400)
    desired = frozenset(capabilities)
    if desired and "view" not in desired:
        raise AccountError("view_required", 400)
    return desired


def _product_permissions():
    return Permission.objects.filter(content_type__app_label="accounts", content_type__model="accountsecurity", codename__in=CAPABILITIES)


def _set_capabilities(user, desired):
    # External grants are immutable through product management, including on
    # locked accounts (whose effective permission helper intentionally returns 0).
    inherited = frozenset(_product_permissions().filter(
        group__in=user.groups.exclude(name__in=PRESET_GROUP_NAMES.values())
    ).values_list("codename", flat=True))
    if not inherited <= desired:
        raise AccountError("inherited_capabilities_required", 409)
    user.groups.remove(*user.groups.filter(name__in=PRESET_GROUP_NAMES.values()))
    user.user_permissions.remove(*_product_permissions())
    for role, grants in PRESETS.items():
        if desired == grants:
            group = Group.objects.filter(name=PRESET_GROUP_NAMES[role]).first()
            expected = {("accounts", "accountsecurity", key) for key in desired}
            if group is not None and set(group.permissions.values_list(
                "content_type__app_label", "content_type__model", "codename"
            )) == expected:
                user.groups.add(group)
                return
            break
    # Technical Admin may edit or rename preset groups. Never grant their
    # changed rights (including unrelated Django permissions) by name alone.
    user.user_permissions.add(*_product_permissions().filter(codename__in=desired - inherited))


def user_snapshot(user):
    security, _ = AccountSecurity.objects.get_or_create(user=user)
    return {
        "display_name": security.display_name,
        "capabilities": sorted(effective_product_permissions(user)),
        "is_active": user.is_active, "is_staff": user.is_staff, "is_superuser": user.is_superuser,
        "has_usable_password": user.has_usable_password(), "generation": security.generation,
    }


def record_user_mutation(*, actor, user, before, action):
    if before.get("is_active") and not user.is_active:
        AccountSecurity.objects.filter(user=user).update(generation=F("generation") + 1)
    AuthAudit.objects.create(
        actor_id=actor.pk, actor_username=actor.username,
        target_id=user.pk, target_username=user.username,
        action=action, before=before, after=user_snapshot(user),
    )


def _product_target(user_id):
    if type(user_id) is not int or user_id <= 0:
        raise AccountError("invalid_request", 400)
    user = get_user_model().objects.filter(pk=user_id).first()
    if user is None:
        raise AccountError("user_not_found", 400)
    if user.is_staff or user.is_superuser:
        raise AccountError("technical_account_readonly", 403)
    return user


def create_product_user(*, actor, username, display_name, password, capabilities, active, **extra):
    with authority_mutation(actor=actor):
        actor = require_product_admin(actor)
        desired = _validate_fields(display_name, capabilities, active, extra)
        validate_product_password(password)
        if type(username) is not str:
            raise AccountError("invalid_username", 400)
        User = get_user_model()
        username = User.normalize_username(username)
        try:
            User._meta.get_field("username").clean(username, None)
        except ValidationError:
            raise AccountError("invalid_username", 400) from None
        if User.objects.filter(username=username).exists():
            raise AccountError("username_exists", 409)
        try:
            # A savepoint keeps a unique-name race from leaking database input.
            with transaction.atomic():
                user = User.objects.create_user(username=username, password=password, is_active=active)
        except IntegrityError:
            raise AccountError("username_exists", 409) from None
        AccountSecurity.objects.filter(user=user).update(display_name=display_name)
        _set_capabilities(user, desired)
        record_user_mutation(actor=actor, user=user, before={}, action="user_created")
    return user


def update_product_user(*, actor, user_id, display_name, capabilities, active, **extra):
    with authority_mutation(actor=actor):
        actor = require_product_admin(actor)
        desired = _validate_fields(display_name, capabilities, active, extra)
        user = _product_target(user_id)
        if actor.pk == user.pk and not active:
            raise AccountError("self_lock", 409)
        before = user_snapshot(user)
        _set_capabilities(user, desired)
        user.is_active = active
        user.save(update_fields=["is_active"])
        AccountSecurity.objects.filter(user=user).update(display_name=display_name)
        record_user_mutation(actor=actor, user=user, before=before, action="user_updated")
    return user


def reset_product_password(*, actor, user_id, new_password):
    with authority_mutation(actor=actor):
        actor = require_product_admin(actor)
        user = _product_target(user_id)
        validate_product_password(new_password)
        before = user_snapshot(user)
        user.set_password(new_password)
        user.save(update_fields=["password"])
        record_user_mutation(actor=actor, user=user, before=before, action="password_reset")
