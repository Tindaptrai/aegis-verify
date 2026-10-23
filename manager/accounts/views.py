from functools import wraps

from django.contrib.auth import authenticate, get_user_model, login, logout
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.views.csrf import csrf_failure as django_csrf_failure

from .contracts import parse_json, permissions_dto, product_user_input, session_dto, user_dto, users_query
from .errors import AccountError
from .permissions import require_product_permission
from .services import change_own_password, create_product_user, reset_product_password, update_product_user


def api_error(code, status):
    response = JsonResponse({"error": {"code": code}}, status=status)
    response["Cache-Control"] = "no-store"
    return response


def human_api(method, *, authenticated=False):
    methods = (method,) if isinstance(method, str) else method

    def decorate(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            try:
                if request.method not in methods:
                    response = api_error("invalid_request", 405)
                    response["Allow"] = ", ".join(methods)
                    return response
                if authenticated and not request.user.is_authenticated:
                    raise AccountError("unauthenticated", 401)
                return view(request, *args, **kwargs)
            except AccountError as error:
                return api_error(error.code, error.status)
            except PermissionError:
                return api_error("permission_denied", 403)
        return wrapped
    return decorate


def _fields(request, names):
    data = parse_json(request)
    if set(data) != set(names) or any(type(data[key]) is not str for key in names):
        raise AccountError("invalid_request", 400)
    return data


@human_api("GET")
def auth_session(request):
    return JsonResponse(session_dto(request))


@human_api("POST")
def auth_login(request):
    data = _fields(request, ("username", "password"))
    user = authenticate(request, username=data["username"], password=data["password"])
    if user is None or not user.is_active:
        raise AccountError("invalid_credentials", 401)
    login(request, user)
    return JsonResponse(session_dto(request))


@human_api("POST")
def auth_logout(request):
    _fields(request, ())
    logout(request)
    return HttpResponse(status=204)


@human_api("POST", authenticated=True)
def auth_password(request):
    data = _fields(request, ("current_password", "new_password"))
    change_own_password(request=request, **data)
    return HttpResponse(status=204)


@human_api(("GET", "POST"), authenticated=True)
def users(request):
    actor = require_product_permission(request.user, "manage_users")
    if request.method == "POST":
        user = create_product_user(actor=actor, **product_user_input(request, creating=True))
        return JsonResponse(user_dto(user, actor), status=201)
    page, search = users_query(request)
    rows = get_user_model().objects.all()
    if search:
        rows = rows.filter(Q(username__icontains=search) | Q(account_security__display_name__icontains=search))
    count = rows.count()
    offset = (page - 1) * 50
    return JsonResponse({"results": [user_dto(user, actor) for user in rows.order_by("username", "pk")[offset:offset + 50]],
                         "count": count, "page": page, "page_size": 50})


@human_api("PUT", authenticated=True)
def user_update(request, user_id):
    actor = require_product_permission(request.user, "manage_users")
    user = update_product_user(actor=actor, user_id=user_id, **product_user_input(request))
    return JsonResponse(user_dto(user, actor))


@human_api("POST", authenticated=True)
def user_reset_password(request, user_id):
    actor = require_product_permission(request.user, "manage_users")
    data = _fields(request, ("new_password",))
    reset_product_password(actor=actor, user_id=user_id, **data)
    return HttpResponse(status=204)


@human_api("GET", authenticated=True)
def user_permissions(request):
    require_product_permission(request.user, "manage_users")
    return JsonResponse(permissions_dto())


def csrf_failure(request, reason=""):
    if request.path_info.startswith("/api/v1/"):
        return api_error("permission_denied", 403)
    return django_csrf_failure(request, reason=reason)
