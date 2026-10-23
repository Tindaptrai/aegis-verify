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


def product_user_input(request, *, creating=False) -> dict:
    data = parse_json(request)
    fields = {"display_name": str, "capabilities": list, "is_active": bool}
    if creating:
        fields.update(username=str, password=str)
    if set(data) != set(fields) or any(type(data[key]) is not kind for key, kind in fields.items()):
        raise AccountError("invalid_request", 400)
    # The service owns capability vocabulary, uniqueness, view prerequisites and
    # account policy. HTTP input alone translates the public active field.
    data["active"] = data.pop("is_active")
    return data


def users_query(request) -> tuple[int, str]:
    query = request.GET
    if set(query) - {"page", "q"} or any(len(query.getlist(key)) != 1 for key in query):
        raise AccountError("invalid_request", 400)
    raw_page, search = query.get("page", "1"), query.get("q", "")
    # Bound integer conversion and database offsets while allowing empty pages.
    if (not raw_page.isascii() or not raw_page.isdecimal() or len(raw_page) > 9
            or int(raw_page) < 1 or len(search) > 100):
        raise AccountError("invalid_request", 400)
    return int(raw_page), search


def permissions_dto() -> dict:
    descriptions = (
        ("Xem dữ liệu", "Xem tổng quan và dữ liệu trong không gian làm việc."),
        ("Chạy tác vụ", "Phê duyệt và hủy các tác vụ kiểm thử trong phạm vi cho phép."),
        ("Nhập kịch bản", "Thêm kịch bản kiểm thử vào thư viện."),
        ("Xuất bản kịch bản", "Xuất bản các phiên bản kịch bản đã được duyệt."),
        ("Quản lý thiết bị", "Quản lý các thiết bị đã đăng ký."),
        ("Quản lý kết nối", "Quản lý các kết nối thu thập dữ liệu."),
        ("Xuất bằng chứng", "Xuất bằng chứng và báo cáo kiểm thử."),
        ("Quản lý tài khoản", "Tạo, cập nhật, khóa và đặt lại mật khẩu tài khoản."),
    )
    return {
        "capabilities": [{"key": key, "label": label, "description": description}
                         for key, (label, description) in zip(CAPABILITIES, descriptions)],
        "presets": {role: [key for key in CAPABILITIES if key in grants] for role, grants in PRESETS.items()},
        "inheritance_explanation": "Quyền kế thừa từ nhóm bên ngoài được giữ lại và không thể gỡ tại đây. Mọi quyền thao tác đều cần quyền xem dữ liệu.",
    }


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
