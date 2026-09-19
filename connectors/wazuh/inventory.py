"""Read-only Wazuh Server API inventory. Administrative metadata, not events."""
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import HTTPException
from pathlib import Path
import re
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler

from aegis_verify.intake.io import decode_config
from aegis_verify.intake.errors import IntakeError


class InventoryError(Exception):
    """Fixed safe codes, never API response text."""


@dataclass(frozen=True)
class InventoryConfig:
    endpoint: str = field(repr=False)
    ca_file: Path = field(repr=False)
    username: str = field(repr=False)
    password: str = field(repr=False)

    def __post_init__(self):
        try:
            url = urlsplit(self.endpoint)
            if (url.scheme != 'https' or not url.hostname or url.username is not None
                    or url.password is not None or url.port == 0 or url.path not in ('', '/')
                    or url.query or url.fragment or '\\' in self.endpoint
                    or any(c.isspace() for c in self.endpoint)
                    or not self.username or ':' in self.username or not self.password
                    or not self.ca_file):
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise InventoryError('invalid_config') from None


@dataclass(frozen=True)
class AgentRecord:
    environment_id: str
    agent_id: str
    name: str | None
    os_name: str | None
    os_version: str | None
    source_status: str | None
    last_keepalive: str | None
    fetched_at: str


def _text(value):
    if value is not None and (type(value) is not str or len(value) > 512):
        raise InventoryError('invalid_agent_record')
    return value


def parse_agent(raw, *, environment_id, fetched_at):
    if type(raw) is not dict or type(raw.get('id')) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', raw['id']):
        raise InventoryError('invalid_agent_record')
    operating_system = raw.get('os')
    if operating_system is None:
        operating_system = {}
    if type(operating_system) is not dict:
        raise InventoryError('invalid_agent_record')
    return AgentRecord(environment_id, raw['id'], _text(raw.get('name')),
        _text(operating_system.get('name')), _text(operating_system.get('version')),
        _text(raw.get('status')), _text(raw.get('lastKeepAlive')), fetched_at)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class InventoryTransport:
    def __init__(self, config):
        self.config = config
        try:
            context = ssl.create_default_context(cafile=str(config.ca_file))
        except (OSError, ssl.SSLError):
            raise InventoryError('invalid_ca') from None
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), _NoRedirect())

    def request(self, method, path, *, token=None):
        login = (method, path) == ('POST', '/security/user/authenticate')
        if not login and (method != 'GET' or not path.startswith('/agents?') or not token):
            raise InventoryError('unsupported_request')
        auth = ('Basic ' + base64.b64encode(f'{self.config.username}:{self.config.password}'.encode()).decode()
                if login else 'Bearer ' + token)
        request = Request(self.config.endpoint.rstrip('/') + path, method=method,
            data=b'' if login else None,
            headers={'Authorization': auth, 'Accept': 'application/json', 'Accept-Encoding': 'identity'})
        try:
            with self.opener.open(request, timeout=10) as response:
                raw = response.read(1024**2 + 1)
            if len(raw) > 1024**2:
                raise InventoryError('response_too_large')
            return raw
        except HTTPError as exc:
            code = {401: 'authentication_failed', 403: 'permission_denied', 429: 'rate_limited'}.get(exc.code, 'http_error')
            exc.close()
            raise InventoryError(code) from None
        except (ssl.SSLError, URLError, OSError, ValueError, HTTPException):
            raise InventoryError('connection_or_tls_failed') from None


def fetch_agents(connection, environment_id, agent_ids, *, transport=None, now=None, clock=time.monotonic):
    if (not 1 <= len(agent_ids) <= 100 or len(set(agent_ids)) != len(agent_ids)
            or any(type(i) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', i) for i in agent_ids)):
        raise InventoryError('invalid_scope')
    transport = transport or InventoryTransport(connection)
    started, byte_count = clock(), 0
    token, retried = None, False
    fetched_at = (now or (lambda: datetime.now(timezone.utc)))().isoformat()

    def request(method, path, bearer=None):
        nonlocal byte_count
        if clock() - started >= 60:
            raise InventoryError('refresh_deadline')
        raw = transport.request(method, path, token=bearer)
        if clock() - started >= 60:
            raise InventoryError('refresh_deadline')
        if type(raw) is not bytes or len(raw) > 1024**2:
            raise InventoryError('response_too_large')
        byte_count += len(raw)
        if byte_count > 5 * 1024**2:
            raise InventoryError('refresh_byte_limit')
        try:
            doc = decode_config(raw, stage='inputs')
        except IntakeError:
            raise InventoryError('invalid_response') from None
        if type(doc.get('error')) is not int or doc['error'] != 0 or type(doc.get('data')) is not dict:
            raise InventoryError('invalid_response')
        return doc['data']

    def login():
        value = request('POST', '/security/user/authenticate').get('token')
        if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,16384}', value):
            raise InventoryError('invalid_token')
        return value

    token = login()
    records, seen = [], set()
    for _ in range(10):
        path = '/agents?' + urlencode({'agents_list': ','.join(agent_ids), 'offset': len(records),
            'limit': 50, 'select': 'id,name,os.name,os.version,status,lastKeepAlive', 'sort': '+id'})
        try:
            data = request('GET', path, token)
        except InventoryError as exc:
            if str(exc) != 'authentication_failed' or retried:
                raise
            retried = True
            token = login()
            data = request('GET', path, token)
        items, total = data.get('affected_items'), data.get('total_affected_items')
        if (type(items) is not list or not items or len(items) > 50
                or type(total) is not int or total != len(agent_ids)
                or data.get('failed_items') != [] or type(data.get('total_failed_items')) is not int
                or data['total_failed_items'] != 0):
            raise InventoryError('incomplete_snapshot')
        for item in items:
            record = parse_agent(item, environment_id=environment_id, fetched_at=fetched_at)
            if record.agent_id not in agent_ids or record.agent_id in seen:
                raise InventoryError('incomplete_snapshot')
            seen.add(record.agent_id)
            records.append(record)
        if len(records) == total:
            return tuple(records)
    raise InventoryError('page_limit')
