"""Offline live-transport contract checks; no lab access."""
import json
import ssl
import io
from urllib.error import HTTPError, URLError
from http.client import IncompleteRead
from pathlib import Path

import pytest

from aegis_verify.connectors.wazuh.live import Config, LiveError, collect, HttpsTransport
from aegis_verify.connectors.wazuh import parse_wazuh_document

ROOT = Path(__file__).resolve().parents[2]
RAW = (ROOT / 'tests/fixtures/wazuh/win4688.sanitized.json').read_bytes()
HIT = json.loads(RAW)
START = '2020-01-01T00:00:00Z'
END = '2030-01-01T00:00:00Z'

def config(**changes):
    return Config(**(dict(endpoint='https://indexer.example.test', username='reader',
                          password='secret-test', index='wazuh-alerts-*', agent_id=HIT['_source']['agent']['id'],
                          start=START, end=END, environment_id='test', collection_mode='direct') | changes))

def page(hits, total=1, **changes):
    return json.dumps(dict(_scroll_id='test-cursor', timed_out=False,
                          _shards=dict(total=1, successful=1, failed=0),
                          hits=dict(total=dict(value=total, relation='eq'), hits=hits)) | changes).encode()

class Transport:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = []

    def request(self, method, path, body):
        self.calls.append((method, path, body))
        if method == 'DELETE':
            return b'{"succeeded":true}'
        result = next(self.pages)
        if isinstance(result, Exception):
            raise result
        return result

def test_collect_preserves_response_and_fixture_mapping(tmp_path):
    raw = page([HIT])
    transport = Transport([raw, page([])])
    out = tmp_path / 'new'
    result = collect(config(), out, transport=transport)
    assert result['record_count'] == 1
    assert result['collection_assurance'] == 'unknown'
    assert (out / 'response-0001.json').read_bytes() == raw
    inputs = json.loads((out / 'inputs.json').read_bytes())
    entry = inputs['files'][0]
    derived = (out / entry['path']).read_bytes()
    assert json.loads(derived) == HIT
    expected = parse_wazuh_document(derived, source_ref=entry['source_ref'],
        environment_id='test', **entry['context']).event.model_dump(mode='json')
    assert json.loads((out / 'canonical.json').read_bytes())[0] == expected
    original = parse_wazuh_document(RAW, source_ref='fixture', environment_id='test', **entry['context']).event.model_dump(mode='json')
    for key in original.keys() - {'event_id', 'raw_event_ref', 'raw_event_hash'}:
        assert expected[key] == original[key]
    assert transport.calls[0][2]['query']['bool']['filter'][0] == {'term': {'agent.id': config().agent_id}}
    assert transport.calls[-1][0] == 'DELETE'
    assert 'secret-test' not in (out / 'collection.json').read_text()

@pytest.mark.parametrize('bad', [
    page([HIT], timed_out=True),
    page([HIT], _shards=dict(total=2, successful=1, failed=1)),
    page([HIT], _shards=dict(total=2, successful=1, failed=0)),
    page([], total=1),
    b'{"hits":',
])
def test_partial_or_invalid_search_never_publishes_inputs(tmp_path, bad):
    out = tmp_path / 'new'
    with pytest.raises(LiveError):
        collect(config(), out, transport=Transport([bad]))
    assert not (out / 'inputs.json').exists()
    assert (out / 'INCOMPLETE').exists()

def test_duplicate_hits_fail_closed_and_clear_scroll(tmp_path):
    t = Transport([page([HIT]), page([HIT])])
    with pytest.raises(LiveError):
        collect(config(), tmp_path / 'new', transport=t)
    assert t.calls[-1][0] == 'DELETE'

def test_existing_output_is_not_overwritten(tmp_path):
    with pytest.raises(LiveError, match='output_exists'):
        collect(config(), tmp_path, transport=Transport([]))

@pytest.mark.parametrize('changes', [dict(endpoint='http://indexer.example.test'),
    dict(endpoint='https://user:pass@indexer.example.test'), dict(index='../_all'),
    dict(index='*'), dict(start=END, end=START), dict(agent_id=''), dict(page_size=0)])
def test_invalid_config_is_safe(changes):
    with pytest.raises(LiveError):
        config(**changes)

def test_secret_not_in_repr_and_tls_verifies():
    cfg = config()
    assert 'secret-test' not in repr(cfg)
    transport = HttpsTransport(cfg)
    assert transport.context.verify_mode == ssl.CERT_REQUIRED
    assert transport.context.check_hostname

def test_empty_search_is_not_a_security_verdict(tmp_path):
    result = collect(config(), tmp_path / 'new', transport=Transport([page([], total=0)]))
    assert result['record_count'] == 0
    assert result['collection_assurance'] == 'unknown'
    assert 'final_status' not in result

@pytest.mark.parametrize('fixture,parser_id', [('sysmon1.synthetic.json', 'wazuh-sysmon1-v1'),
                                            ('powershell4104.synthetic.json', 'wazuh-powershell4104-v1')])
def test_windows_profiles_reuse_fixture_mapping(tmp_path, fixture, parser_id):
    from aegis_verify.connectors.wazuh.live import PROFILES
    raw = (ROOT / 'tests/fixtures/wazuh/windows-telemetry' / fixture).read_bytes()
    hit = json.loads(raw) | {'_id': 'fixture-id', '_index': 'wazuh-alerts-test'}
    out = tmp_path / 'new'
    collect(config(), out, transport=Transport([page([hit]), page([])]))
    entry = json.loads((out / 'inputs.json').read_bytes())['files'][0]
    assert entry['parser'] == parser_id
    parser = next(p for name, p in PROFILES.values() if name == parser_id)
    original = parser(raw, source_ref='fixture', environment_id='test', **entry['context']).event.model_dump(mode='json')
    actual = json.loads((out / 'canonical.json').read_bytes())[0]
    for key in original.keys() - {'event_id', 'raw_event_ref', 'raw_event_hash'}:
        assert actual[key] == original[key]

def test_multiple_pages_keep_all_records(tmp_path):
    second = json.loads(RAW)
    second['_id'] = 'other'
    t = Transport([page([HIT], total=2), page([second], total=2), page([], total=2)])
    assert collect(config(page_size=1), tmp_path / 'new', transport=t)['record_count'] == 2
    assert t.calls[1][1] == '/_search/scroll'

@pytest.mark.parametrize('changes', [dict(max_records=1), dict(max_pages=1)])
def test_record_and_page_limits_do_not_publish(tmp_path, changes):
    with pytest.raises(LiveError):
        collect(config(**changes), tmp_path / 'new', transport=Transport([page([HIT], total=2)]))
    assert not (tmp_path / 'new/inputs.json').exists()

def test_connection_failure_does_not_return_partial(tmp_path):
    t = Transport([page([HIT], total=2), LiveError('connection_or_tls_failed')])
    with pytest.raises(LiveError):
        collect(config(), tmp_path / 'new', transport=t)
    assert t.calls[-1][0] == 'DELETE'
    assert not (tmp_path / 'new/inputs.json').exists()

@pytest.mark.parametrize('status,code', [(401,'authentication_failed'),(403,'permission_denied'),
                                      (302,'http_error'),(503,'http_error'),(429,'rate_limited')])
def test_http_failures_redact_secrets_and_bound_retries(monkeypatch, status, code):
    transport = HttpsTransport(config())
    attempts = []
    def fail(*args, **kwargs):
        attempts.append(1)
        raise HTTPError('https://secret-test.example', status, 'secret-test', {}, io.BytesIO(b'secret-test'))
    monkeypatch.setattr(transport._opener, 'open', fail)
    monkeypatch.setattr('aegis_verify.connectors.wazuh.live.time.sleep', lambda _: None)
    with pytest.raises(LiveError, match=code) as error:
        transport.request('POST', '/wazuh-alerts-*/_search?scroll=1m', {})
    assert 'secret-test' not in str(error.value)
    assert len(attempts) == (3 if status == 429 else 1)

def test_ambiguous_scroll_connection_failure_is_not_retried(monkeypatch):
    t = HttpsTransport(config())
    attempts = []
    def fail(*args, **kwargs):
        attempts.append(1)
        raise URLError('secret-test')
    monkeypatch.setattr(t._opener, 'open', fail)
    with pytest.raises(LiveError, match='connection_or_tls_failed'):
        t.request('POST', '/_search/scroll', {'scroll_id': 'test'})
    assert len(attempts) == 1

def test_transport_refuses_unrelated_routes():
    with pytest.raises(LiveError, match='unsupported_request'):
        HttpsTransport(config()).request('DELETE', '/wazuh-alerts-test', {})

def test_collection_profile_is_explicit_in_query(tmp_path):
    t = Transport([page([], total=0)])
    collect(config(), tmp_path / 'new', transport=t)
    scope = t.calls[0][2]['query']['bool']['filter'][2]
    assert scope['bool']['minimum_should_match'] == 1
    assert len(scope['bool']['should']) == 3

def test_truncated_http_body_is_redacted(monkeypatch):
    transport = HttpsTransport(config())
    def fail(*args, **kwargs):
        raise IncompleteRead(b'secret-test')
    monkeypatch.setattr(transport._opener, 'open', fail)
    with pytest.raises(LiveError, match='connection_or_tls_failed'):
        transport.request('POST', '/_search/scroll', {})

def test_out_of_scope_hit_is_rejected(tmp_path):
    wrong = json.loads(RAW)
    wrong['_source']['agent']['id'] = 'different-agent'
    with pytest.raises(LiveError, match='scope_mismatch'):
        collect(config(), tmp_path / 'new', transport=Transport([page([wrong])]))

def test_cleanup_failure_is_explicit(tmp_path):
    class FailingCleanup(Transport):
        def request(self, method, path, body):
            if method == 'DELETE':
                raise LiveError('permission_denied')
            return super().request(method, path, body)
    result = collect(config(), tmp_path / 'new', transport=FailingCleanup([page([],total=0)]))
    assert result['cleanup_failed'] is True


@pytest.mark.parametrize('retry_after', ['11', 'later', '999', '-1'])
def test_invalid_retry_after_aborts_without_sleep(monkeypatch, retry_after):
    transport = HttpsTransport(config())
    def fail(*args, **kwargs):
        raise HTTPError('https://indexer.example.test', 429, 'test',
                        {'Retry-After': retry_after}, io.BytesIO(b'private'))
    monkeypatch.setattr(transport._opener, 'open', fail)
    monkeypatch.setattr('aegis_verify.connectors.wazuh.live.time.sleep',
                        lambda _: pytest.fail('must not sleep on invalid retry header'))
    with pytest.raises(LiveError, match='^rate_limited$'):
        transport.request('POST', '/wazuh-alerts-*/_search?scroll=1m', {})


def test_bounded_retry_can_recover(monkeypatch):
    transport = HttpsTransport(config())
    responses = iter([HTTPError('https://indexer.example.test', 429, 'test',
                               {'Retry-After':'3'}, io.BytesIO(b'private')), io.BytesIO(b'{}')])
    waits = []
    def respond(*args, **kwargs):
        value = next(responses)
        if isinstance(value, HTTPError):
            raise value
        return value
    monkeypatch.setattr(transport._opener, 'open', respond)
    monkeypatch.setattr('aegis_verify.connectors.wazuh.live.time.sleep', waits.append)
    assert transport.request('POST', '/wazuh-alerts-*/_search?scroll=1m', {}) == b'{}'
    assert waits == [3]


def test_transport_rejects_oversized_response(monkeypatch):
    from aegis_verify.connectors.wazuh._json import MAX_BYTES
    transport = HttpsTransport(config())
    monkeypatch.setattr(transport._opener, 'open', lambda *a, **kw: io.BytesIO(b'x'*(MAX_BYTES+1)))
    with pytest.raises(LiveError, match='^response_too_large$'):
        transport.request('POST', '/wazuh-alerts-*/_search?scroll=1m', {})
