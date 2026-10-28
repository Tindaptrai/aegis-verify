"""Exact human and verified-mTLS machine execution routes."""
import importlib
from functools import wraps
from django.db import OperationalError, InterfaceError
from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from accounts.permissions import require_product_permission
from accounts.views import human_api, api_error
from devices.contracts import DeviceError
from devices.identity import certificate_fingerprint
from . import execution_contracts as wire
from . import execution_services as service


def response(data, status=200):
    result=HttpResponse(wire.canonical_bytes(data), status=status, content_type='application/json')
    result['Cache-Control']='no-store'
    return result


def body(request):
    if request.content_type != 'application/json' or request.GET:
        raise ValueError('invalid_request')
    if int(request.META.get('CONTENT_LENGTH') or 0) > wire.REQUEST_LIMIT:
        raise ValueError('invalid_request')
    raw=request.body
    if len(raw)>wire.REQUEST_LIMIT: raise ValueError('invalid_request')
    return raw


def execution_api(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        try:
            result=view(request,*args,**kwargs)
            result['Cache-Control']='no-store'
            return result
        except wire.ExecutionError as error:
            return response(error.response,error.status)
        except (OperationalError,InterfaceError,OSError):
            return api_error('execution_unavailable',503)
        except (ValueError,TypeError,KeyError,UnicodeError):
            return api_error('invalid_request',400)
    return wrapped


@execution_api
@human_api('GET',authenticated=True)
def providers(request):
    require_product_permission(request.user,'view')
    if request.GET: raise ValueError()
    return response(service.execution_providers(request.user))


@execution_api
@human_api('GET',authenticated=True)
def device(request, device_id):
    require_product_permission(request.user,'view')
    if request.GET: raise ValueError()
    return response(service.get_execution_device(request.user,str(device_id),now=timezone.now()))


@execution_api
@human_api('PUT',authenticated=True)
def binding(request, device_id):
    require_product_permission(request.user,'manage_devices')
    return response(service.set_execution_binding(request.user,str(device_id),wire.parse_execution_request('binding',body(request))))


@execution_api
@human_api('POST',authenticated=True)
def preview(request):
    require_product_permission(request.user,'run_jobs')
    return response(service.preview_execution(request.user,wire.parse_execution_request('preview',body(request)),now=timezone.now()),201)


@execution_api
@human_api('POST',authenticated=True)
def approve(request):
    require_product_permission(request.user,'run_jobs')
    result,created=service._approve_execution(request.user,wire.parse_execution_request('approve',body(request)),now=timezone.now())
    return response(result,201 if created else 200)


@execution_api
@human_api('GET',authenticated=True)
def current_job(request):
    require_product_permission(request.user,'view')
    if request.GET: raise ValueError()
    return response(service.current_execution_job(request.user))


@execution_api
@human_api('GET',authenticated=True)
def job(request,job_id):
    require_product_permission(request.user,'view')
    if request.GET: raise ValueError()
    return response(service.get_execution_job(request.user,str(job_id)))


@execution_api
@human_api('POST',authenticated=True)
def cancel(request,job_id):
    require_product_permission(request.user,'run_jobs')
    if wire.load_json(body(request)) != {}: raise ValueError()
    return response(service.cancel_execution(request.user,str(job_id)))


@csrf_exempt
def machine(request, operation, job_id=None):
    try:
        # Authenticate proxy/certificate before parsing a Job reference or querying jobs.
        fingerprint=certificate_fingerprint(request)
        if request.method!='POST': return api_error('invalid_request',405)
        raw=body(request)
        parsed=wire.parse_execution_request(operation,raw)
        identity=service.ExecutionIdentity(parsed.device_id,parsed.generation,fingerprint)
        now=timezone.now()
        service.authenticate_execution_identity(identity,now=now)
        if operation=='poll':
            result=service.poll_execution(identity,parsed,now=now)
            output=HttpResponse(result,status=200 if result is not None else 204,content_type='application/json')
        elif operation=='start':
            output=HttpResponse(service.authorize_execution_start(identity,str(job_id),raw,now=now),content_type='application/json')
        elif operation=='receipt':
            output=HttpResponse(service.accept_execution_receipt(identity,raw,now=now),content_type='application/json')
        else:
            try: readiness=importlib.import_module('control.execution_readiness')
            except ModuleNotFoundError as error:
                if error.name!='control.execution_readiness': raise
                raise wire.ExecutionError('temporarily_unavailable') from None
            output=response(readiness.record_local_readiness(identity,parsed,received_at=now))
        output['Cache-Control']='no-store'
        return output
    except (DeviceError,PermissionError):
        return api_error('identity_denied',403)
    except wire.ExecutionError as error:
        code=error.code
        if code in ('binding_conflict','job_conflict','preview_conflict'):
            code='start_conflict' if operation=='start' else 'lease_conflict'
        if code=='execution_unavailable': code='temporarily_unavailable'
        return api_error(code,wire.ERRORS[code])
    except (OperationalError,InterfaceError,OSError):
        return api_error('temporarily_unavailable',503)
    except (ValueError,TypeError,KeyError,UnicodeError):
        return api_error('invalid_request',400)
