from functools import wraps

from django.db import OperationalError, InterfaceError
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from accounts.permissions import require_product_permission
from accounts.views import api_error, human_api
from control.models import Device
from .contracts import DeviceError, device_dto, devices_query, parse_json
from .identity import require_https
from .services import create_pairing_code, revoke_pairing_code, revoke_device, enroll_device, receive_heartbeat


def devices_api(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        try:
            response = view(request, *args, **kwargs)
            response["Cache-Control"] = "no-store"
            return response
        except DeviceError as error:
            return api_error(error.code, error.status)
    return wrapped


@devices_api
@human_api("GET", authenticated=True)
def devices(request):
    require_product_permission(request.user, "view")
    page, search = devices_query(request)
    rows = Device.objects.all()
    if search:
        rows = rows.filter(Q(hostname__icontains=search) | Q(environment_id__icontains=search) | Q(wazuh_agent_id__icontains=search))
    offset = (page - 1) * 50
    return JsonResponse({"results": [device_dto(row) for row in rows.order_by("pk")[offset:offset + 50]],
                         "count": rows.count(), "page": page, "page_size": 50})


@devices_api
@human_api("POST", authenticated=True)
def pairing_codes(request):
    require_product_permission(request.user, "manage_devices")
    data = parse_json(request)
    if set(data) != {"environment_id"}:
        raise DeviceError("invalid_request")
    return JsonResponse(create_pairing_code(actor=request.user, **data), status=201)


@devices_api
@human_api("POST", authenticated=True)
def pairing_code_revoke(request, code_id):
    require_product_permission(request.user, "manage_devices")
    if parse_json(request) != {}:
        raise DeviceError("invalid_request")
    revoke_pairing_code(actor=request.user, code_id=code_id)
    return HttpResponse(status=204)


@devices_api
@human_api("POST", authenticated=True)
def device_revoke(request, device_id):
    require_product_permission(request.user, "manage_devices")
    if parse_json(request) != {}:
        raise DeviceError("invalid_request")
    revoke_device(actor=request.user, device_id=device_id)
    return HttpResponse(status=204)


def machine_api(view):
    @csrf_exempt
    @devices_api
    @wraps(view)
    def wrapped(request):
        if request.method != "POST":
            response = api_error("invalid_request", 405)
            response["Allow"] = "POST"
            return response
        try:
            return view(request)
        except (OperationalError, InterfaceError):
            return api_error("temporarily_unavailable" if view.__name__ == "heartbeat" else "issuer_unavailable", 503)
    return wrapped


@machine_api
def enroll(request):
    data = parse_json(request)
    require_https(request)
    return JsonResponse(enroll_device(data), status=201)


@machine_api
def heartbeat(request):
    return JsonResponse(receive_heartbeat(request=request, data=parse_json(request)))
