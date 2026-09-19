import json
from dataclasses import replace
from datetime import datetime, timezone
from threading import Event
from uuid import uuid4

import pytest

from aegis_verify.dashboard.operations_config import OperationsConfig, ConnectionConfig, OperationsError
from aegis_verify.dashboard.operations_storage import JobStore
from aegis_verify.dashboard.operations_jobs import JobService, CollectionRequest
from aegis_verify.connectors.wazuh import live
from test_operations_storage import record


NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)
RESULT = dict(record_count=0, query_complete=True, collection_assurance='unknown', cleanup_failed=False)


def request(**changes):
    data = dict(agent_id='012', start='2026-01-01T00:00:00Z',
                end='2026-01-01T00:01:00Z', adaptive=True, request_id=str(uuid4()))
    return CollectionRequest(**{**data, **changes})


@pytest.fixture
def factory(tmp_path):
    services = []
    release = Event()
    def create(collector=None, cfg=None, free=2 * 1024**3, store=None):
        config = cfg or OperationsConfig('fixture', ('012',), 'wazuh-alerts-*', tmp_path,
            ConnectionConfig('https://indexer.invalid', tmp_path / 'ca.pem', 'reader', 'private-marker'))
        service = JobService(config, store or JobStore(tmp_path),
            collect_fn=collector or (lambda *args, **kwargs: RESULT.copy()),
            now=lambda: NOW, free_bytes=lambda path: free)
        services.append(service)
        return service
    yield create, release
    release.set()
    for service in services:
        service.shutdown()


def test_single_job_idempotent_and_busy(factory):
    create, release = factory
    def collect(cfg, output, *, adaptive):
        assert cfg.agent_id == '012' and cfg.password == 'private-marker'
        assert adaptive is True and not output.exists()
        assert release.wait(10)
        return RESULT.copy()
    service = create(collect)
    req = request()
    first = service.submit(req)
    assert first['state'] == 'running'
    assert service.submit(req)['id'] == first['id']
    with pytest.raises(OperationsError, match='job_busy'):
        service.submit(request())
    with pytest.raises(OperationsError, match='request_conflict'):
        service.submit(replace(req, adaptive=False))
    release.set()
    service.shutdown()
    assert service.get_job(first['id'])['state'] == 'completed'
    assert service.get_job(first['id'])['result'] == RESULT
    assert 'private-marker' not in json.dumps(service.list_jobs())


@pytest.mark.parametrize('changes', [dict(agent_id='../x'), dict(request_id='bad'),
    dict(adaptive=1), dict(start='yesterday'), dict(end='2025-01-01T00:00:00Z'),
    dict(start='2026-01-01T00:00:00'), dict(end='2026-01-01T00:00:00Z')])
def test_invalid_request(changes):
    with pytest.raises(OperationsError):
        request(**changes)


@pytest.mark.parametrize('changes', [dict(agent_id='009'),
    dict(end='2026-01-02T00:00:00.000000001Z'), dict(start='2025-12-30T00:00:00Z')])
def test_admission_scope_and_window(factory, changes):
    create, _ = factory
    with pytest.raises(OperationsError):
        create().submit(request(**changes))


def test_low_disk_rejected_without_job(factory):
    create, _ = factory
    service = create(free=2 * 1024**3 - 1)
    with pytest.raises(OperationsError, match='disk_space'):
        service.submit(request())
    assert service.list_jobs() == []


def test_unconfigured_rejected(factory, tmp_path):
    create, _ = factory
    service = create(cfg=OperationsConfig('fixture', ('012',), 'wazuh-alerts-*', tmp_path))
    with pytest.raises(OperationsError, match='not_configured'):
        service.submit(request())


@pytest.mark.parametrize('result,error', [
    ({**RESULT, 'query_complete': False}, 'incomplete_collection'),
    (RuntimeError('password=private-marker'), 'collection_failed'),
    (live.LiveError('permission_denied'), 'permission_denied'),
    (live.LiveError('private-marker'), 'collection_failed'),
])
def test_failed_collection_never_success(factory, result, error):
    create, _ = factory
    def collect(*args, **kwargs):
        if isinstance(result, Exception):
            raise result
        return result
    service = create(collect)
    job = service.submit(request())
    service.shutdown()
    assert service.get_job(job['id'])['state'] == 'failed'
    assert service.get_job(job['id'])['error_code'] == error
    assert 'private-marker' not in json.dumps(service.list_jobs())


def test_cleanup_warning_remains_visible(factory):
    create, _ = factory
    service = create(lambda *a, **kw: {**RESULT, 'cleanup_failed': True})
    job = service.submit(request())
    service.shutdown()
    assert service.get_job(job['id'])['state'] == 'completed'
    assert service.get_job(job['id'])['result']['cleanup_failed'] is True


def test_restart_interrupts_without_replay(factory, tmp_path):
    store = JobStore(tmp_path)
    store.save(record())
    create, _ = factory
    def no_call(*args, **kwargs):
        pytest.fail('recovered work replayed')
    service = create(no_call)
    assert service.get_job(record()['id'])['state'] == 'interrupted'
    assert store.load()[0]['state'] == 'interrupted'


def test_corrupt_store_blocks_submit(factory, tmp_path):
    store = JobStore(tmp_path)
    (tmp_path / 'metadata' / 'bad.json').write_text('{}')
    create, _ = factory
    service = create(store=store)
    with pytest.raises(OperationsError, match='invalid_job_metadata'):
        service.submit(request())


def test_persistence_failure_never_runs_collector(factory, tmp_path, monkeypatch):
    store = JobStore(tmp_path)
    def failed(record):
        raise OperationsError('storage_failed')
    monkeypatch.setattr(store, 'save', failed)
    create, _ = factory
    service = create(lambda *a, **kw: pytest.fail('collector ran'), store=store)
    with pytest.raises(OperationsError, match='storage_failed'):
        service.submit(request())


def test_real_collector_fixture_bundle(factory, tmp_path):
    from test_wazuh_live import Transport, page, HIT
    from copy import deepcopy
    create, _ = factory
    hit = deepcopy(HIT)
    hit['_source']['agent']['id'] = '012'
    hit['_source']['timestamp'] = '2026-01-01T00:00:30Z'
    def collect(cfg, output, *, adaptive):
        return live.collect(cfg, output, transport=Transport([page([hit]), page([])]))
    service = create(collect)
    job = service.submit(request(adaptive=False))
    service.shutdown()
    assert service.get_job(job['id'])['result']['record_count'] == 1
    canonical = tmp_path / 'jobs' / job['id'] / 'bundle' / 'canonical.json'
    assert len(json.loads(canonical.read_bytes())) == 1


def test_terminal_persistence_failure_blocks_followup(factory, tmp_path, monkeypatch):
    store = JobStore(tmp_path)
    original = store.save
    def save(value):
        if value['state'] != 'running':
            raise OperationsError('storage_failed')
        original(value)
    monkeypatch.setattr(store, 'save', save)
    create, release = factory
    finished = Event()
    def collect(*a, **kw):
        finished.set()
        return RESULT.copy()
    service = create(collect, store=store)
    job = service.submit(request())
    service.shutdown()
    assert service.get_job(job['id'])['state'] == 'failed'
    assert service.get_job(job['id'])['error_code'] == 'storage_failed'


def test_concurrent_same_request_runs_once(factory):
    from concurrent.futures import ThreadPoolExecutor
    create, release = factory
    calls = []
    def collect(*a, **kw):
        calls.append(1)
        release.wait(10)
        return RESULT.copy()
    service = create(collect)
    req = request()
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = list(pool.map(service.submit, [req] * 4))
    assert len({job['id'] for job in jobs}) == 1
    release.set()
    service.shutdown()
    assert calls == [1]


def test_job_limit_at_service(factory, tmp_path):
    store = JobStore(tmp_path)
    for n in range(1, 101):
        store.save({**record(n), 'state': 'interrupted',
                    'finished_at': '2026-01-01T02:00:00Z', 'error_code': 'interrupted'})
    create, _ = factory
    service = create(store=store)
    with pytest.raises(OperationsError, match='job_limit'):
        service.submit(request())
    assert len(service.list_jobs()) == 100


def test_second_service_cannot_recover_active_jobs(factory):
    create, release = factory
    def collect(*args, **kwargs):
        release.wait(10)
        return RESULT.copy()
    first = create(collect)
    job = first.submit(request())
    with pytest.raises(OperationsError, match='root_in_use'):
        create()
    assert first.get_job(job['id'])['state'] == 'running'
    release.set()
    first.shutdown()
    restarted = create()
    assert restarted.get_job(job['id'])['state'] == 'completed'


def test_root_cannot_be_reused_for_different_environment(factory, tmp_path):
    create, _ = factory
    first = create()
    first.shutdown()
    changed = OperationsConfig('different', ('012',), 'wazuh-alerts-*', tmp_path)
    with pytest.raises(OperationsError, match='root_scope_mismatch'):
        create(cfg=changed)
