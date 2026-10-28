"""Offline read-only health contracts, with no source or evidence writes."""
import json
from dataclasses import asdict
import pytest
from aegis_verify.connectors.wazuh import live


def config():
    return live.Config(endpoint='https://indexer.example.test', username='synthetic-reader',
        password='synthetic-test-only', index='wazuh-alerts-*', agent_id='901',
        start='2026-01-01T00:00:00Z', end='2026-01-01T00:01:00Z', environment_id='synthetic')


class Transport:
    def __init__(self, response): self.response, self.calls = response, []
    def request(self, method, path, body):
        self.calls.append((method, path, body))
        if isinstance(self.response, Exception): raise self.response
        return json.dumps(self.response).encode()


def response(**changes):
    return dict(timed_out=False, _shards=dict(total=1, successful=1, failed=0),
        hits=dict(total=dict(value=0, relation='eq'), hits=[])) | changes


def test_zero_hits_probe_is_healthy_without_events_or_scroll():
    t = Transport(response())
    result = live.probe(config(), transport=t)
    assert asdict(result) == {'healthy': True, 'code': 'healthy'}
    assert len(t.calls) == 1
    method, path, body = t.calls[0]
    assert (method, path, body['size']) == ('POST', '/wazuh-alerts-*/_search', 0)
    assert body['query']['bool']['filter'][0] == {'term': {'agent.id': '901'}}


@pytest.mark.parametrize('value', [response(timed_out=True), response(terminated_early=True),
    response(_shards=dict(total=1, successful=0, failed=1)), response(_shards=dict(total=2, successful=1, failed=0)),
    response(_shards=dict(total=True, successful=True, failed=0)), {},
    live.LiveError('authentication_failed'), live.LiveError('connection_or_tls_failed')])
def test_unverified_or_partial_probe_blocks(value):
    assert asdict(live.probe(config(), transport=Transport(value))) == {'healthy': False, 'code': 'source_unavailable'}


def test_probe_uses_verified_existing_transport(monkeypatch):
    seen = []
    def transport(cfg):
        seen.append(cfg)
        raise live.LiveError('invalid_ca')
    monkeypatch.setattr(live, 'HttpsTransport', transport)
    assert live.probe(config()).healthy is False
    assert len(seen) == 1
