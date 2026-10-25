import base64
import json
import re
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from django.db import transaction
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from .identity import authenticate_device
from .jobs import claim_job, lock_dispatch, audit, HEX
from .models import Job, Device, AuditEntry
from .execution_ownership import lock_device_ownership, guard_execution_owner


def pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError("Duplicate property")
        result[key] = value
    return result


def parse(request):
    if request.method != "POST" or request.content_type != "application/json": raise ValueError()
    if int(request.META.get("CONTENT_LENGTH") or 0) > 65536: raise ValueError()
    raw = request.body
    if len(raw) > 65536: raise ValueError()
    body = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if not isinstance(body, dict) or body.get("protocol") != "0.1.0": raise ValueError()
    return body, raw.decode("utf-8")


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",value): raise ValueError()
    return datetime.strptime(value,"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt_timezone.utc)


def canonical_uuid(value):
    if not isinstance(value,str) or str(uuid.UUID(value)) != value: raise ValueError()


@csrf_exempt
def endpoint(request, job_id=None, operation="poll"):
    try:
        device = authenticate_device(request)
        body, raw = parse(request)
        if operation == "poll":
            if set(body) != {"protocol"}: raise ValueError()
            job = claim_job(device)
            return JsonResponse(job.envelope) if job else HttpResponse(status=204)
        with transaction.atomic():
            lock_dispatch()
            lock_device_ownership(device.pk)
            device = Device.objects.select_for_update().get(pk=device.pk)
            if device.revoked or device.archived_at is not None: raise PermissionError()
            if operation == 'start': guard_execution_owner(device)
            try: job = Job.objects.select_for_update().select_related("release").get(pk=job_id,device=device,protocol_family='legacy_v1')
            except Job.DoesNotExist: raise PermissionError() from None
            if job.approved_generation != device.generation: raise PermissionError()
            if operation == "start":
                if set(body) != {"protocol", "payload_sha256"}: raise ValueError()
                if body["payload_sha256"] != job.payload_sha256 or job.execution_state != "leased" or not job.not_before <= timezone.now() <= job.expires_at:
                    return JsonResponse({"error":"lease_conflict"},status=409)
                job.execution_state = "started"
                job.started_authorized_at = timezone.now()
                job.save(update_fields=["execution_state", "started_authorized_at"])
                audit(job,"start_authorized",device.pk)
                return JsonResponse({"authorized":True})
            if set(body) != {"protocol", "receipt_id", "job_id", "payload_sha256", "state", "started_at", "finished_at", "exit_code", "cleanup_succeeded"}: raise ValueError()
            canonical_uuid(body["receipt_id"]); canonical_uuid(body["job_id"])
            if body["job_id"] != str(job.id) or body["payload_sha256"] != job.payload_sha256: raise ValueError()
            if body["state"] not in ("succeeded", "failed", "execution_unknown") or type(body["cleanup_succeeded"]) is not bool or (body["exit_code"] is not None and (type(body["exit_code"]) is not int or not -2147483648 <= body["exit_code"] <= 2147483647)): raise ValueError()
            if body["state"] == "succeeded" and (body["exit_code"] != 0 or not body["cleanup_succeeded"]): raise ValueError()
            end = timestamp(body["finished_at"])
            if body["state"] == "execution_unknown":
                if not job.not_before <= end <= timezone.now() + timedelta(seconds=5): raise ValueError()
                if body["started_at"] is not None:
                    start = timestamp(body["started_at"])
                    if not job.not_before <= start <= job.expires_at or end < start: raise ValueError()
            else:
                start = timestamp(body["started_at"])
                if not job.not_before <= start <= job.expires_at or not start <= end <= start + timedelta(seconds=json.loads(base64.b64decode(job.envelope["payload"]))["timeout_seconds"]) or not job.collection_start <= start <= end <= job.collection_end: raise ValueError()
            if job.receipt is not None:
                return JsonResponse({"accepted":True}) if raw == job.receipt_bytes else JsonResponse({"error":"receipt_conflict"},status=409)
            late_unknown = body["state"] == "execution_unknown" and job.execution_state in ("leased", "execution_unknown", "cancelled", "expired")
            if late_unknown:
                if not AuditEntry.objects.filter(job=job, action="leased").exists():
                    return JsonResponse({"error":"execution_conflict"},status=409)
            elif job.execution_state != "started":
                return JsonResponse({"error":"execution_conflict"},status=409)
            job.receipt, job.receipt_bytes = body, raw
            if job.execution_state in ("started", "leased"):
                job.execution_state = body["state"]
                job.save(update_fields=["receipt", "receipt_bytes", "execution_state"])
            else:
                job.save(update_fields=["receipt", "receipt_bytes"])
            audit(job,"receipt_accepted",device.pk)
            return JsonResponse({"accepted":True})
    except PermissionError:
        return JsonResponse({"error":"identity_denied"}, status=403)
    except (ValueError, TypeError, KeyError, UnicodeError):
        return JsonResponse({"error":"invalid_request"}, status=400)
