"""Closed human contracts; source secrets never enter presentation."""
import json
import re
import uuid
from accounts.contracts import _unique_object, _invalid_constant
from aegis_verify.connectors.wazuh.onboarding import origin, validate_index, validate_ca

FIELDS = {'name','environment_id','endpoint','index','username','password','ca_pem','source_id','expected_version'}


class ConnectionError(Exception):
    def __init__(self, code, status):
        if code not in {'invalid_request','permission_denied','draft_expired','draft_conflict',
                        'source_conflict','candidate_conflict','rate_limited'}:
            raise ValueError('invalid_connection_error')
        self.code, self.status = code, status
        super().__init__(code)


def fail(code='invalid_request', status=400):
    raise ConnectionError(code, status)


def uuid_value(value, nullable=False):
    if value is None and nullable:
        return None
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError
        return value
    except (ValueError, TypeError, AttributeError):
        fail()


def parse(request, fields):
    try:
        raw = request._connections_body
        if request.content_type != 'application/json' or request.GET:
            raise ValueError
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if type(data) is not dict or set(data) != set(fields):
            raise ValueError
        return data
    except (ValueError, UnicodeError, RecursionError, AttributeError):
        fail()


def test_input(data):
    if type(data) is not dict or set(data) != FIELDS:
        fail()
    for key, maximum in (('name',80), ('environment_id',64), ('username',128), ('password',1024), ('endpoint',2048), ('index',128)):
        value = data[key]
        if type(value) is not str or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
            fail()
        try:
            value.encode('utf-8')
        except UnicodeError:
            fail()
    if ':' in data['username'] or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', data['environment_id']):
        fail()
    uuid_value(data['source_id'], nullable=True)
    if data['source_id'] is None:
        if data['expected_version'] is not None:
            fail()
    elif type(data['expected_version']) is not int or not 1 <= data['expected_version'] <= 2147483647:
        fail()
    try:
        if type(data['ca_pem']) is not str or len(data['ca_pem'].encode('utf-8')) > 65536:
            fail()
    except UnicodeError:
        fail()
    origin(data['endpoint'])
    validate_index(data['index'])
    return validate_ca(data['ca_pem'])


def page_number(request):
    if set(request.GET) - {'page'} or any(len(request.GET.getlist(key)) != 1 for key in request.GET):
        fail()
    value = request.GET.get('page','1')
    if not value.isascii() or not value.isdecimal() or len(value) > 9 or int(value) < 1:
        fail()
    return int(value)
