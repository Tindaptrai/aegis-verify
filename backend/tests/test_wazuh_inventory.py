"""Synthetic Server API snapshots, not canonical security events."""
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from aegis_verify.connectors.wazuh.inventory import (
    InventoryConfig, InventoryError, fetch_agents, parse_agent)


def config():
    return InventoryConfig('https://server.invalid', Path('synthetic.pem'), 'reader', 'secret-marker')


def page(items, total=None, **changes):
    return json.dumps({'error': 0, 'data': {'affected_items': items,
        'total_affected_items': len(items) if total is None else total,
        'failed_items': [], 'total_failed_items': 0, **changes}}).encode()


class Transport:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = []

    def request(self, method, path, *, token=None):
        self.calls.append((method, path, token))
        if method == 'POST':
            assert path == '/security/user/authenticate'
            return b'{"error":0,"data":{"token":"synthetic-token"}}'
        value = next(self.pages)
        if isinstance(value, Exception):
            raise value
        return value


def test_unknown_fields_not_guessed():
    value = parse_agent({'id': '012', 'status': 'future_status'},
        environment_id='fixture', fetched_at='2026-01-01T00:00:00Z')
    assert value.name is None and value.os_name is None and value.last_keepalive is None
    assert value.source_status == 'future_status'


def test_allowlist_paginated_without_unscoped_query():
    ids = tuple(f'{n:03}' for n in range(60))
    t = Transport([page([{'id': i, 'status': 'active'} for i in ids[:50]], 60),
                   page([{'id': i} for i in ids[50:]], 60)])
    result = fetch_agents(config(), 'fixture', ids, transport=t)
    assert tuple(r.agent_id for r in result) == ids
    requests = [parse_qs(urlsplit(p).query) for m, p, _ in t.calls if m == 'GET']
    assert [q['offset'] for q in requests] == [['0'], ['50']]
    assert all(q['agents_list'] == [','.join(ids)] and q['limit'] == ['50'] for q in requests)
    assert 'secret-marker' not in repr(result)


@pytest.mark.parametrize('raw', [page([]), page([{'id': '999'}]),
    page([{'id': '012'}, {'id': '012'}], 1), page([{'id': '012'}], 1, failed_items=[{}]),
    page([{'id': '012'}], True), b'{bad', b'x' * (1024**2 + 1)],
    ids=['missing', 'scope', 'duplicate', 'partial', 'boolean-total', 'malformed', 'oversize'])
def test_invalid_snapshot_never_published(raw):
    with pytest.raises(InventoryError):
        fetch_agents(config(), 'fixture', ('012',), transport=Transport([raw]))


def test_token_expiry_one_retry_only():
    t = Transport([InventoryError('authentication_failed'), page([{'id': '012'}])])
    assert len(fetch_agents(config(), 'fixture', ('012',), transport=t)) == 1
    assert [m for m, _, _ in t.calls] == ['POST', 'GET', 'POST', 'GET']
    t = Transport([InventoryError('authentication_failed')] * 3)
    with pytest.raises(InventoryError, match='authentication_failed'):
        fetch_agents(config(), 'fixture', ('012',), transport=t)
    assert len(t.calls) == 4


@pytest.mark.parametrize('second_page', ['duplicate', 'changed-total', 'missing'])
def test_cross_page_membership_failure_keeps_last_snapshot(tmp_path, second_page):
    from aegis_verify.dashboard.operations_inventory import InventoryService
    from aegis_verify.dashboard.operations_config import OperationsConfig, ConnectionConfig
    from test_operations_inventory import wait_idle
    ids = tuple(f'{n:03}' for n in range(60))
    good = [page([{'id': i, 'status': 'active'} for i in ids[:50]], 60),
            page([{'id': i, 'status': 'active'} for i in ids[50:]], 60)]
    bad = {'duplicate': page([{'id': ids[0]}] + [{'id': i} for i in ids[51:]], 60),
           'changed-total': page([{'id': i} for i in ids[50:]], 59),
           'missing': page([], 60)}[second_page]
    transports = iter([Transport(good), Transport([good[0], bad])])
    clock = [0]
    def fetch(connection, environment, allowlist):
        return fetch_agents(connection, environment, allowlist, transport=next(transports))
    cfg = OperationsConfig('fixture', ids, 'wazuh-alerts-*', tmp_path,
        server_api=ConnectionConfig('https://server.invalid', tmp_path / 'ca.pem', 'r', 'p'))
    service = InventoryService(cfg, fetch_fn=fetch, clock=lambda: clock[0])
    try:
        service.refresh()
        wait_idle(service)
        previous = service.snapshot()
        assert previous['state'] == 'ready' and len(previous['agents']) == 60
        clock[0] = 31
        service.refresh()
        wait_idle(service)
        failed = service.snapshot()
        assert failed['state'] == 'stale' and failed['error_code'] == 'incomplete_snapshot'
        assert failed['agents'] == previous['agents']
        assert failed['fetched_at'] == previous['fetched_at']
    finally:
        service.shutdown()


@pytest.mark.parametrize('code', ['permission_denied', 'rate_limited', 'connection_or_tls_failed'])
def test_source_errors_not_retried(code):
    t = Transport([InventoryError(code)])
    with pytest.raises(InventoryError, match=code):
        fetch_agents(config(), 'fixture', ('012',), transport=t)
    assert len(t.calls) == 2


def test_deadline_stops_before_next_request():
    ticks = iter([0, 0, 61])
    t = Transport([])
    with pytest.raises(InventoryError, match='refresh_deadline'):
        fetch_agents(config(), 'fixture', ('012',), transport=t, clock=lambda: next(ticks))
    assert len(t.calls) == 1


def test_final_response_past_deadline_is_not_published():
    clock = [0]
    class SlowTransport(Transport):
        def request(self, method, path, *, token=None):
            raw = super().request(method, path, token=token)
            if method == 'GET':
                clock[0] = 61
            return raw
    with pytest.raises(InventoryError, match='refresh_deadline'):
        fetch_agents(config(), 'fixture', ('012',),
            transport=SlowTransport([page([{'id': '012'}])]), clock=lambda: clock[0])


@pytest.mark.parametrize('url', ['http://host.invalid', 'https://u:p@host.invalid',
    'https://host.invalid/path', 'https://host.invalid?query=x'])
def test_inventory_config_validates_source(url):
    with pytest.raises(InventoryError):
        InventoryConfig(url, Path('ca.pem'), 'reader', 'secret')


def test_total_byte_bound_and_page_bound():
    ids = tuple(f'{n:03}' for n in range(100))
    pages = [page([{'id': i}], 100, padding='x' * 900000) for i in ids[:10]]
    with pytest.raises(InventoryError, match='refresh_byte_limit'):
        fetch_agents(config(), 'fixture', ids, transport=Transport(pages))
    t = Transport([page([{'id': i}], 100) for i in ids[:11]])
    with pytest.raises(InventoryError, match='page_limit'):
        fetch_agents(config(), 'fixture', ids, transport=t)
    assert len(t.calls) == 11  # One login, exactly ten pages.


def test_transport_tls_proxy_and_request_boundary(monkeypatch):
    import ssl
    from urllib.request import HTTPSHandler, ProxyHandler
    from aegis_verify.connectors.wazuh import inventory
    context = ssl.create_default_context()
    handlers = []
    requests = []
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self, limit):
            assert limit == 1024**2 + 1
            return b'{}'
    class Opener:
        def open(self, request, timeout):
            requests.append((request, timeout))
            return Response()
    def build(*args):
        handlers.extend(args)
        return Opener()
    monkeypatch.setattr(inventory.ssl, 'create_default_context', lambda *, cafile: context)
    monkeypatch.setattr(inventory, 'build_opener', build)
    transport = inventory.InventoryTransport(config())
    transport.request('POST', '/security/user/authenticate')
    transport.request('GET', '/agents?agents_list=012', token='synthetic-token')
    with pytest.raises(InventoryError, match='unsupported_request'):
        transport.request('DELETE', '/agents?agents_list=012', token='synthetic-token')
    assert [r.method for r, _ in requests] == ['POST', 'GET']
    assert requests[1][0].get_header('Authorization') == 'Bearer synthetic-token'
    assert all(timeout == 10 for _, timeout in requests)
    assert next(h for h in handlers if isinstance(h, ProxyHandler)).proxies == {}
    tls = next(h for h in handlers if isinstance(h, HTTPSHandler))._context
    assert tls.verify_mode == ssl.CERT_REQUIRED and tls.check_hostname


@pytest.mark.parametrize('status,code', [(401, 'authentication_failed'), (403, 'permission_denied'),
    (429, 'rate_limited'), (500, 'http_error')])
def test_http_errors_have_fixed_code(monkeypatch, status, code):
    import ssl
    from urllib.error import HTTPError
    from aegis_verify.connectors.wazuh import inventory
    context = ssl.create_default_context()
    monkeypatch.setattr(inventory.ssl, 'create_default_context', lambda **kw: context)
    class Opener:
        def open(self, *args, **kwargs):
            raise HTTPError('https://private.invalid', status, 'secret-marker', {}, None)
    monkeypatch.setattr(inventory, 'build_opener', lambda *a: Opener())
    with pytest.raises(InventoryError, match='^' + code + '$'):
        inventory.InventoryTransport(config()).request('POST', '/security/user/authenticate')
