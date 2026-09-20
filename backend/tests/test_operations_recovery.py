"""Recovery contract with a test-owned process; never contacts a live source.

The collector is a fixture boundary. Storage, OS lease, job worker, and restart
recovery are real. ACL policy has separate tests and is bypassed only here.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Event
import time
from uuid import uuid4

from aegis_verify.dashboard import operations_config
from aegis_verify.dashboard.operations_config import ConnectionConfig, OperationsConfig
from aegis_verify.dashboard.operations_jobs import CollectionRequest, JobService
from aegis_verify.dashboard.operations_storage import JobStore


PAYLOAD = b'fixture-only partial evidence; not a security event\n'
SUMMARY = dict(record_count=0, query_complete=True,
               collection_assurance='unknown', cleanup_failed=False)


def _child(mode, root):
    operations_config._check_private_acl = lambda path: None
    config = OperationsConfig('recovery-fixture', ('012',), 'wazuh-alerts-*', root,
        ConnectionConfig('https://indexer.invalid', root / 'unused-ca.pem',
                         'fixture', uuid4().hex))

    def collect(cfg, output, *, adaptive):
        assert cfg.environment_id == 'recovery-fixture' and adaptive is True
        with (root / 'calls').open('ab') as stream:
            stream.write(b'called\n')
        output.mkdir()
        (output / 'fixture.bin').write_bytes(PAYLOAD)
        if mode == 'crash':
            # Signal only after intent and fixture bytes have been persisted.
            (root / 'ready').write_text('ready', encoding='utf-8')
            Event().wait(60)
        return SUMMARY.copy()

    service = JobService(config, JobStore(root), collect_fn=collect,
                         free_bytes=lambda path: 2 * 1024**3)
    try:
        if mode in ('complete', 'crash'):
            service.submit(CollectionRequest('012', '2026-01-01T00:00:00Z',
                '2026-01-01T00:01:00Z', True, str(uuid4())))
        print(json.dumps(service.list_jobs()), flush=True)
    finally:
        service.shutdown()


def test_killed_worker_recovers_without_replay_or_evidence_changes(tmp_path):
    """Catches lost OS leases, replay, false completion, or destructive recovery."""
    command = [sys.executable, str(Path(__file__).resolve())]
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('WAZUH_')}
    options = dict(env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))

    def run(mode):
        result = subprocess.run(command + [mode, str(tmp_path)],
                                timeout=20, **options)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    run('complete')
    completed_path, = (tmp_path / 'metadata').glob('*.json')
    completed_bytes = completed_path.read_bytes()
    assert json.loads(completed_bytes)['state'] == 'completed'
    child = subprocess.Popen(command + ['crash', str(tmp_path)], **options)
    try:
        deadline = time.monotonic() + 20
        while not (tmp_path / 'ready').exists():
            assert child.poll() is None, child.communicate(timeout=5)
            assert time.monotonic() < deadline, 'fixture worker did not start'
            time.sleep(0.02)
        records = [json.loads(path.read_bytes())
                   for path in (tmp_path / 'metadata').glob('*.json')]
        running, = [record for record in records if record['state'] == 'running']
        evidence = {path.relative_to(tmp_path): path.read_bytes()
                    for path in (tmp_path / 'jobs').rglob('*') if path.is_file()}
        assert len(evidence) == 2
        assert all(value == PAYLOAD for value in evidence.values())
        assert (tmp_path / 'calls').read_bytes() == b'called\ncalled\n'
        child.kill()  # Only this test's child, never a user server or tunnel.
        child.communicate(timeout=10)
        assert child.returncode != 0
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)

    # Two fresh processes also prove recovery is durable and repeatable.
    for _ in range(2):
        recovered = {record['id']: record for record in run('recover')}
        assert len(recovered) == 2
        interrupted = recovered[running['id']]
        assert interrupted['state'] == 'interrupted'
        assert interrupted['error_code'] == 'interrupted'
        assert interrupted['result'] is None
        assert interrupted['finished_at'] is not None
        assert json.loads((tmp_path / 'metadata' / (running['id'] + '.json')).read_bytes()) == interrupted
        assert completed_path.read_bytes() == completed_bytes
        assert {path.relative_to(tmp_path): path.read_bytes()
                for path in (tmp_path / 'jobs').rglob('*') if path.is_file()} == evidence
        assert (tmp_path / 'calls').read_bytes() == b'called\ncalled\n'


if __name__ == '__main__':
    _child(sys.argv[1], Path(sys.argv[2]))
