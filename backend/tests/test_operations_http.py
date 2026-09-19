"""Exercise the real HTTP boundary; no lab/network source requests."""
from http.client import HTTPConnection
import json
from pathlib import Path
import socket
from threading import Thread
from uuid import uuid4

import pytest

from aegis_verify.dashboard.server import make_server
from aegis_verify.dashboard import operations_config, operations_jobs


@pytest.fixture
def server_factory(tmp_path, monkeypatch):
    servers = []
    monkeypatch.setattr(operations_config, '_check_private_acl', lambda path: None)
    monkeypatch.setattr(operations_jobs, '_collect', lambda *a, **kw: {
        'record_count': 0, 'query_complete': True,
        'collection_assurance': 'unknown', 'cleanup_failed': False})
    monkeypatch.setenv('WAZUH_INDEXER_USERNAME', 'reader')
    monkeypatch.setenv('WAZUH_INDEXER_PASSWORD', 'private-marker')
    def create(enabled=True, inventory=False):
        root = tmp_path / str(uuid4())
        root.mkdir()
        reports, output = root / 'reports', root / 'private'
        reports.mkdir()
        output.mkdir(mode=0o700)
        ca = root / 'ca.pem'
        ca.write_text('synthetic-ca')
        path = root / 'config.json'
        data = dict(version=1, environment_id='fixture', agent_ids=['012'],
            index='wazuh-alerts-*', output_root=str(output), indexer={
                'endpoint': 'https://indexer.invalid', 'ca_file': str(ca)})
        if inventory:
            data['server_api'] = {'endpoint': 'https://server.invalid', 'ca_file': str(ca)}
            monkeypatch.setenv('WAZUH_API_USERNAME', 'api-reader')
            monkeypatch.setenv('WAZUH_API_PASSWORD', 'api-private-marker')
        path.write_text(json.dumps(data))
        kwargs = {'operations_config': path} if enabled else {}
        server = make_server(reports, port=0, **kwargs)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return server, output
    yield create
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join()


def call(server, method='GET', route='bootstrap', body=None, headers=None):
    connection = HTTPConnection('127.0.0.1', server.server_port, timeout=3)
    try:
        connection.request(method, '/api/operations/' + route, body=body,
            headers={'X-Aegis-Client': 'operations-v1', **(headers or {})})
        response = connection.getresponse()
        return response.status, dict(response.headers), json.loads(response.read())
    finally:
        connection.close()


def mutation_headers(server, token):
    return {'Origin': f'http://127.0.0.1:{server.server_port}',
            'Content-Type': 'application/json', 'X-Aegis-Session': token}


def test_default_off(server_factory):
    server, _ = server_factory(False)
    assert call(server)[0] == 404


def test_bootstrap_safe_and_reports_unchanged(server_factory):
    server, _ = server_factory()
    status, headers, body = call(server)
    assert status == 200 and body['environment_id'] == 'fixture'
    assert body['agent_ids'] == ['012']
    assert body['capabilities'] == {'collection': True, 'inventory': False}
    assert len(body['session_token']) >= 32
    assert headers['Cache-Control'] == 'no-store'
    text = json.dumps(body)
    assert not any(value in text for value in ('private-marker', 'indexer.invalid', 'ca.pem'))
    connection = HTTPConnection('127.0.0.1', server.server_port)
    connection.request('GET', '/api/reports')
    response = connection.getresponse()
    assert response.status == 200 and json.loads(response.read())['reports'] == []
    connection.close()


@pytest.mark.parametrize('headers', [
    {'Host': 'evil.invalid'}, {'Host': 'localhost'}, {'Origin': 'https://evil.invalid'},
    {'Sec-Fetch-Site': 'cross-site'}, {'Sec-Fetch-Site': 'same-site'},
    {'X-Aegis-Client': ''},
])
def test_bootstrap_rejects_foreign_requests(server_factory, headers):
    server, _ = server_factory()
    assert call(server, headers=headers)[0] == 403


def test_valid_collection_and_session_isolation(server_factory):
    server, _ = server_factory()
    other, _ = server_factory()
    token = call(server)[2]['session_token']
    assert call(other, route='collections', headers={'X-Aegis-Session': token})[0] == 403
    headers = mutation_headers(server, token)
    body = json.dumps(dict(agent_id='012', start='2026-01-01T00:00:00Z',
        end='2026-01-01T00:01:00Z', adaptive=True, request_id=str(uuid4())))
    status, _, job = call(server, 'POST', 'collections', body, headers)
    assert status == 202 and job['state'] in ('running', 'completed')
    status, _, again = call(server, 'POST', 'collections', body, headers)
    assert status == 202 and again['id'] == job['id']
    assert call(server, route='collections/' + job['id'], headers={'X-Aegis-Session': token})[0] == 200


@pytest.mark.parametrize('change,want', [({'Origin': ''}, 403),
    ({'Origin': 'http://evil.invalid'}, 403), ({'X-Aegis-Session': 'wrong'}, 403),
    ({'Content-Type': 'text/plain'}, 415)])
def test_mutation_protection(server_factory, change, want):
    server, _ = server_factory()
    headers = {**mutation_headers(server, call(server)[2]['session_token']), **change}
    assert call(server, 'POST', 'collections', '{}', headers)[0] == want


@pytest.mark.parametrize('body,want', [('x' * 8193, 413), ('{bad', 400),
    ('{"command":"anything"}', 400), ('{"agent_id":"012","agent_id":"012"}', 400)],
    ids=['oversize', 'malformed', 'unknown-keys', 'duplicate-keys'])
def test_body_limits(server_factory, body, want):
    server, _ = server_factory()
    headers = mutation_headers(server, call(server)[2]['session_token'])
    assert call(server, 'POST', 'collections', body, headers)[0] == want


@pytest.mark.parametrize('framing', ['Content-Length: 2\r\nContent-Length: 2',
    'Transfer-Encoding: chunked', 'Content-Length: -1', 'Content-Length: nope'])
def test_ambiguous_framing_rejected(server_factory, framing):
    server, _ = server_factory()
    token = call(server)[2]['session_token']
    request = (f'POST /api/operations/collections HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\n'
        f'Origin: http://127.0.0.1:{server.server_port}\r\nX-Aegis-Client: operations-v1\r\n'
        f'X-Aegis-Session: {token}\r\nContent-Type: application/json\r\n{framing}\r\n\r\n{{}}')
    with socket.create_connection(('127.0.0.1', server.server_port), timeout=3) as connection:
        connection.sendall(request.encode())
        assert b' 400 ' in connection.recv(4096).split(b'\r\n')[0]


def test_inventory_not_configured_and_no_raw_route(server_factory):
    server, _ = server_factory()
    token = call(server)[2]['session_token']
    headers = {'X-Aegis-Session': token}
    assert call(server, route='agents', headers=headers)[2]['state'] == 'not_configured'
    assert call(server, route='collections/%2e%2e', headers=headers)[0] == 404
    assert call(server, route='raw', headers=headers)[0] == 404


def test_nonloopback_operations_rejected(tmp_path):
    with pytest.raises(operations_config.OperationsError):
        make_server(tmp_path, host='0.0.0.0', port=0, operations_config=tmp_path / 'missing')


def test_incomplete_body_is_rejected(server_factory):
    server, _ = server_factory()
    token = call(server)[2]['session_token']
    request = (f'POST /api/operations/collections HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\n'
        f'Origin: http://127.0.0.1:{server.server_port}\r\nX-Aegis-Client: operations-v1\r\n'
        f'X-Aegis-Session: {token}\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n{{}}')
    with socket.create_connection(('127.0.0.1', server.server_port), timeout=3) as connection:
        connection.sendall(request.encode())
        connection.shutdown(socket.SHUT_WR)
        assert b' 400 ' in connection.recv(4096).split(b'\r\n')[0]


def test_inventory_api_refresh_is_explicit(server_factory, monkeypatch):
    import time
    from aegis_verify.dashboard import operations_inventory
    from aegis_verify.connectors.wazuh.inventory import parse_agent
    calls = []
    def fetch(*args):
        calls.append(args[2])
        return (parse_agent({'id': '012', 'status': 'active'},
                environment_id='fixture', fetched_at='2026-01-01T00:00:00Z'),)
    monkeypatch.setattr(operations_inventory, 'fetch_agents', fetch)
    server, _ = server_factory(inventory=True)
    boot = call(server)[2]
    assert boot['capabilities']['inventory'] is True
    token = boot['session_token']
    headers = mutation_headers(server, token)
    assert call(server, route='agents', headers=headers)[2]['state'] == 'unavailable'
    assert calls == []
    assert call(server, 'POST', 'agents/refresh', '{}', headers)[0] == 202
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        snapshot = call(server, route='agents', headers=headers)[2]
        if not snapshot['refreshing']:
            break
        time.sleep(0.01)
    assert snapshot['state'] == 'ready' and calls == [('012',)]
    assert call(server, 'POST', 'agents/refresh', '{}', headers)[0] == 429
