"""Persistence is bounded, atomic and does not serve arbitrary metadata."""
import json
from uuid import UUID

import pytest

from aegis_verify.dashboard.operations_config import OperationsError
from aegis_verify.dashboard import operations_storage as storage
from aegis_verify.dashboard import operations_config as config


@pytest.fixture(autouse=True)
def isolated_acl(monkeypatch):
    monkeypatch.setattr(config, '_check_private_acl', lambda path: None)


def test_existing_public_child_rejected(tmp_path, monkeypatch):
    (tmp_path / 'jobs').mkdir()
    def check(path):
        if path.name == 'jobs':
            raise OperationsError('private_root_required')
    monkeypatch.setattr(config, '_check_private_acl', check)
    with pytest.raises(OperationsError, match='private_root_required'):
        storage.JobStore(tmp_path)


def test_public_persisted_metadata_rejected(tmp_path, monkeypatch):
    store = storage.JobStore(tmp_path)
    store.save(record())
    def check(path):
        if path.suffix == '.json':
            raise OperationsError('private_root_required')
    monkeypatch.setattr(config, '_check_private_acl', check)
    with pytest.raises(OperationsError, match='private_root_required'):
        store.load()


def record(n=1):
    return dict(id=str(UUID(int=n)), request_id=str(UUID(int=n + 1000)), agent_id='012',
                start='2026-01-01T00:00:00Z', end='2026-01-01T00:01:00Z', adaptive=True,
                state='running', created_at='2026-01-01T01:00:00Z', finished_at=None,
                result=None, error_code=None)


def test_store_roundtrip_and_no_overwrite(tmp_path):
    store = storage.JobStore(tmp_path)
    store.save(record())
    assert storage.JobStore(tmp_path).load() == [record()]
    output = store.new_output(record()['id'])
    assert output.is_dir() and output.parent == tmp_path / 'jobs'
    with pytest.raises(OperationsError):
        store.new_output(record()['id'])


@pytest.mark.parametrize('change', [{'password': 'secret'}, {'state': 'Detected'},
    {'id': '../escape'}, {'adaptive': 1}, {'result': {'record_count': -1}},
    {'error_code': 'secret exception text'}, {'agent_id': '../x'}])
def test_untrusted_record_rejected(tmp_path, change):
    store = storage.JobStore(tmp_path)
    with pytest.raises(OperationsError):
        store.save({**record(), **change})
    assert store.load() == []


def test_corrupt_metadata_blocks_load(tmp_path):
    store = storage.JobStore(tmp_path)
    path = tmp_path / 'metadata' / (record()['id'] + '.json')
    for content in ('{bad', 'x' * 16385, json.dumps({**record(), 'password': 'secret'})):
        path.write_text(content)
        with pytest.raises(OperationsError):
            store.load()


def test_job_limit_preserves_existing(tmp_path):
    store = storage.JobStore(tmp_path)
    for n in range(1, 101):
        store.save(record(n))
    with pytest.raises(OperationsError):
        store.save(record(101))
    assert len(store.load()) == 100
    store.save({**record(), 'state': 'interrupted', 'finished_at': '2026-01-01T02:00:00Z',
                'error_code': 'interrupted'})
    assert len(store.load()) == 100


def test_atomic_replace_failure_preserves_record(tmp_path, monkeypatch):
    store = storage.JobStore(tmp_path)
    store.save(record())
    def fail(*args):
        raise OSError('sensitive path')
    monkeypatch.setattr(storage.os, 'replace', fail)
    with pytest.raises(OperationsError) as error:
        store.save({**record(), 'state': 'interrupted', 'finished_at': '2026-01-01T02:00:00Z',
                    'error_code': 'interrupted'})
    assert 'sensitive' not in str(error.value)
    assert store.load() == [record()]


def test_filename_mismatch_rejected(tmp_path):
    store = storage.JobStore(tmp_path)
    (tmp_path / 'metadata' / (record(2)['id'] + '.json')).write_text(json.dumps(record()))
    with pytest.raises(OperationsError):
        store.load()
