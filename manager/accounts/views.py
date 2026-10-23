from functools import wraps

from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, JsonResponse
from django.views.csrf import csrf_failure as django_csrf_failure

from .contracts import parse_json, session_dto
from .errors import AccountError
from .services import change_own_password


def api_error(code, status):
    response = JsonResponse({"error": {"code": code}}, status=status)
    response["Cache-Control"] = "no-store"
    return response


def human_api(method, *, authenticated=False):
    def decorate(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            try:
                if request.method != method:
                    response = api_error("invalid_request", 405)
                    response["Allow"] = method
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


def csrf_failure(request, reason=""):
    if request.path_info.startswith("/api/v1/"):
        return api_error("permission_denied", 403)
    return django_csrf_failure(request, reason=reason)
