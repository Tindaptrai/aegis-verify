"""Same-origin local operations boundary; no Wazuh credential enters this layer."""
import hmac
import re

from .operations_config import OperationsError


def _one(headers, name):
    values = headers.get_all(name, []) if hasattr(headers, 'get_all') else (
        [headers[name]] if name in headers else [])
    if len(values) > 1:
        raise OperationsError('forbidden')
    return values[0] if values else None


def authorize(method, path, headers, *, authority, token):
    origin = 'http://' + authority
    if (_one(headers, 'Host') != authority
            or _one(headers, 'X-Aegis-Client') != 'operations-v1'
            or _one(headers, 'Sec-Fetch-Site') not in (None, 'same-origin', 'none')
            or _one(headers, 'Origin') not in (None, origin)):
        raise OperationsError('forbidden')
    if (method, path) != ('GET', '/api/operations/bootstrap'):
        supplied = _one(headers, 'X-Aegis-Session') or ''
        if not supplied.isascii() or not hmac.compare_digest(supplied, token):
            raise OperationsError('forbidden')
    if method != 'GET' and _one(headers, 'Origin') != origin:
        raise OperationsError('forbidden')


def body_length(method, headers):
    if headers.get('Transfer-Encoding') is not None:
        raise OperationsError('invalid_request')
    lengths = headers.get_all('Content-Length', []) if hasattr(headers, 'get_all') else (
        [headers['Content-Length']] if 'Content-Length' in headers else [])
    if len(lengths) > 1:
        raise OperationsError('invalid_request')
    raw = lengths[0] if lengths else None
    if raw is not None and (not re.fullmatch(r'[0-9]{1,10}', raw)):
        raise OperationsError('invalid_request')
    length = int(raw or 0)
    if length > 8192:
        raise OperationsError('body_too_large')
    if method == 'GET':
        if length:
            raise OperationsError('invalid_request')
    else:
        if raw is None:
            raise OperationsError('invalid_request')
        if _one(headers, 'Content-Type') != 'application/json':
            raise OperationsError('unsupported_media')
    return length
