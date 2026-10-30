from functools import wraps
from django.http import JsonResponse
from accounts.views import human_api, api_error
from accounts.permissions import require_product_permission
from aegis_verify.connectors.wazuh.onboarding import ProbeError
from .storage import StorageError
from . import contracts, services


def connection_api(method):
    def decorator(view):
        @human_api(method, authenticated=True)
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            require_product_permission(request.user, 'manage_connections')
            try:
                return view(request, *args, **kwargs)
            except contracts.ConnectionError as error:
                return api_error(error.code,error.status)
            except ProbeError as error:
                code = str(error)
                status = 429 if code == 'rate_limited' else 400 if code in ('invalid_request','invalid_ca') else 409
                return api_error(code, status)
            except StorageError:
                return api_error('storage_unavailable',503)
        return wrapped
    return decorator


@connection_api('GET')
def sources(request):
    return JsonResponse(services.list_sources(contracts.page_number(request)))


@connection_api('POST')
def test_wazuh(request):
    return JsonResponse(services.test_connection(request, contracts.parse(request, contracts.FIELDS)),status=201)


@connection_api('POST')
def save_wazuh(request):
    data = contracts.parse(request, {'draft_id','idempotency_key'})
    result, created = services.save_connection(request, **data)
    return JsonResponse(result,status=201 if created else 200)


@connection_api('POST')
def prepare(request, source_id):
    data = contracts.parse(request, {'expected_candidate_id'})
    return JsonResponse(services.prepare_connection(request, source_id, **data))
