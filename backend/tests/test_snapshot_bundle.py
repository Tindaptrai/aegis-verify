"""Transport tests use synthetic inputs and owned temporary directories only."""

from dataclasses import replace
import hashlib
import importlib
import json
import os
from pathlib import Path
import tempfile

import pytest

from aegis_verify.connectors.wazuh.manager_snapshot import ManagerSnapshotScope
from aegis_verify.cli.service import evaluate_bundle
from aegis_verify import private_fs
from windows_acl import assert_owner_only

FIXTURES = Path(__file__).resolve().parents[2] / 'tests/fixtures/wazuh/windows-telemetry'


@pytest.fixture
def api():
    return importlib.import_module('aegis_verify.demo.snapshot_bundle')


@pytest.fixture
def lab():
    # Outside Git; no production bypass for a test or raw lab path.
    with tempfile.TemporaryDirectory(prefix='aegis-synthetic-transport-') as directory:
        yield Path(directory)


@pytest.fixture
def sample(api, lab):
    records = []
    for name in ('sysmon1', 'powershell4104'):
        record = json.loads((FIXTURES / (name + '.synthetic.json')).read_bytes())['_source']
        record['decoder'] = {'name': 'windows_eventchannel'}
        records.append(json.dumps(record, separators=(',', ':')).encode())
    records[0] = records[0][:-1] + b', "synthetic_unknown":1.2300e+02}'
    raw = b'\xef\xbb\xbf' + records[0] + b'\r\n\n' + records[1]
    source = lab / 'source.jsonl'
    source.write_bytes(raw)
    snapshots = (api.SnapshotFile(source, 'synthetic-day', hashlib.sha256(raw).hexdigest()),)
    scope = ManagerSnapshotScope('901', 'synthetic-endpoint', 'synthetic-env',
                                 '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z',
                                 '2026-01-01T00:03:00Z')
    return snapshots, dict(scope=scope, profile=(FIXTURES / 'profile.json').read_bytes(),
                          context=(FIXTURES / 'context.json').read_bytes(), destination=lab / 'bundle')


def test_roundtrip_preserves_source_ledger_and_real_cli_evidence(api, sample):
    snapshots, kwargs = sample
    out = api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert out.samefile(kwargs['destination'])
    result = api.verify_snapshot_bundle(out)
    raw = snapshots[0].path.read_bytes()
    assert (out / 'snapshots' / (snapshots[0].sha256 + '.jsonl')).read_bytes() == raw
    assert result.collection_assurance == 'unknown'
    ledger = json.loads((out / 'ledger.json').read_bytes())
    assert len(ledger['lines']) == 3
    assert ledger['lines'][0]['line_sha256'] == hashlib.sha256(raw.splitlines(keepends=True)[0]).hexdigest()
    assert ledger['lines'][0]['byte_offset'] == 0
    assert ledger['lines'][0]['bom_removed'] is True
    assert ledger['lines'][1]['disposition'] == 'bookkeeping'
    assert b'1.2300e+02' in (out / ledger['lines'][0]['document_path']).read_bytes()
    assert (out / 'profile.json').read_bytes() == kwargs['profile']
    assert (out / 'context.json').read_bytes() == kwargs['context']
    report = evaluate_bundle(FIXTURES.parents[3] / 'scenarios/SCN-001-powershell-execution.yaml', out)
    assert report['evaluation']['final_status'] == 'Inconclusive'
    assert report['evaluation']['assertions'][2]['reason_code'] == 'collection_not_confirmed'
    assert {x['event_id'] for x in report['evaluation']['evidence_index']} == {
        d.telemetry.event.event_id for d in result.documents}


@pytest.mark.parametrize('which', ['environment_id', 'start', 'end', 'declarations'])
def test_rejects_context_scope_drift_or_assurance_before_output(api, sample, which):
    snapshots, kwargs = sample
    context = json.loads(kwargs['context'])
    context[which] = {'environment_id': 'different', 'start': '2026-01-01T00:00:01Z',
                      'end': '2026-01-01T00:01:01Z', 'declarations': [{}]}[which]
    kwargs['context'] = json.dumps(context).encode()
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert not kwargs['destination'].exists()


@pytest.mark.parametrize('which', ['profile', 'context'])
@pytest.mark.parametrize('raw', [b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.1}', b'PRIVATE_CANARY'])
def test_bad_configs_have_no_output_or_payload_diagnostic(api, sample, which, raw):
    snapshots, kwargs = sample
    kwargs[which] = raw
    with pytest.raises(api.SnapshotBundleError) as caught:
        api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert 'PRIVATE_CANARY' not in str(caught.value)
    assert not kwargs['destination'].exists()


def test_snapshot_hash_mismatch_stops_before_writes(api, sample):
    snapshots, kwargs = sample
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle((replace(snapshots[0], sha256='0' * 64),), **kwargs)
    assert not kwargs['destination'].exists()


def test_existing_destination_is_never_overwritten(api, sample):
    snapshots, kwargs = sample
    kwargs['destination'].mkdir()
    marker = kwargs['destination'] / 'user.txt'
    marker.write_bytes(b'owned by user')
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert marker.read_bytes() == b'owned by user'
    assert list(kwargs['destination'].iterdir()) == [marker]


@pytest.mark.parametrize('bad', ['../escape', 'bundle/../escape', 'NUL', 'bad:stream', 'bad*name', 'bad.', 'bad '])
def test_output_unsafe_spelling_is_rejected(api, sample, lab, bad):
    snapshots, kwargs = sample
    kwargs['destination'] = str(lab) + '/' + bad
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle(snapshots, **kwargs)


def test_output_inside_git_is_rejected(api, sample, lab):
    snapshots, kwargs = sample
    (lab / '.git').mkdir()
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert not kwargs['destination'].exists()


def test_input_hardlink_alias_is_rejected(api, sample, lab):
    snapshots, kwargs = sample
    os.link(snapshots[0].path, lab / 'alias.jsonl')
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert not kwargs['destination'].exists()


def test_incomplete_directory_never_verifies(api, lab):
    (lab / 'inputs.json').write_bytes(b'{}')
    with pytest.raises(api.SnapshotBundleError):
        api.verify_snapshot_bundle(lab)


@pytest.mark.parametrize('name', ['ledger.json', 'inputs.json', 'profile.json', 'context.json',
                                'snapshot-bundle.json', 'source', 'document'])
def test_tampered_bundle_is_rejected(api, sample, name):
    snapshots, kwargs = sample
    out = api.prepare_snapshot_bundle(snapshots, **kwargs)
    if name == 'source':
        path = next((out / 'snapshots').iterdir())
    elif name == 'document':
        path = next((out / 'documents').iterdir())
    else:
        path = out / name
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(api.SnapshotBundleError):
        api.verify_snapshot_bundle(out)


def test_extra_file_not_hidden_by_manifest(api, sample):
    snapshots, kwargs = sample
    out = api.prepare_snapshot_bundle(snapshots, **kwargs)
    (out / 'unlisted.txt').write_bytes(b'not evidence')
    with pytest.raises(api.SnapshotBundleError):
        api.verify_snapshot_bundle(out)


def test_forged_ledger_and_updated_manifest_hash_still_fail_reconstruction(api, sample):
    snapshots, kwargs = sample
    out = api.prepare_snapshot_bundle(snapshots, **kwargs)
    path = out / 'ledger.json'
    ledger = json.loads(path.read_bytes())
    ledger['lines'][0]['byte_offset'] = 1
    path.write_bytes(json.dumps(ledger, sort_keys=True, separators=(',', ':')).encode())
    manifest_path = out / 'snapshot-bundle.json'
    manifest = json.loads(manifest_path.read_bytes())
    manifest['files']['ledger.json'] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_bytes(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode())
    with pytest.raises(api.SnapshotBundleError):
        api.verify_snapshot_bundle(out)


def test_failed_write_keeps_partial_without_completion_or_source_changes(api, sample, monkeypatch):
    snapshots, kwargs = sample
    before = snapshots[0].path.read_bytes()
    real_write = api.write_file

    def interrupted(root, relative, raw):
        if relative.startswith('documents/'):
            raise OSError('PRIVATE_CANARY simulated disk error')
        real_write(root, relative, raw)

    monkeypatch.setattr(api, 'write_file', interrupted)
    with pytest.raises(api.SnapshotBundleError) as caught:
        api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert str(caught.value) == 'invalid_snapshot_bundle'
    assert kwargs['destination'].is_dir()
    assert not (kwargs['destination'] / 'snapshot-bundle.json').exists()
    assert snapshots[0].path.read_bytes() == before
    with pytest.raises(api.SnapshotBundleError):
        api.verify_snapshot_bundle(kwargs['destination'])


def test_failed_read_never_creates_output(api, sample, monkeypatch):
    snapshots, kwargs = sample

    def denied(*args):
        raise PermissionError('PRIVATE_CANARY')

    monkeypatch.setattr(api, 'read_file', denied)
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert not kwargs['destination'].exists()


def test_ledger_limit_fails_before_output_not_truncates(api, sample):
    snapshots, kwargs = sample
    raw = b'\n' * 5000
    snapshots[0].path.write_bytes(raw)
    snapshots = (replace(snapshots[0], sha256=hashlib.sha256(raw).hexdigest()),)
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert not kwargs['destination'].exists()


def test_empty_snapshot_retains_unknown_not_fabricated_events(api, sample):
    _, kwargs = sample
    out = api.prepare_snapshot_bundle((), **kwargs)
    result = api.verify_snapshot_bundle(out)
    assert result.documents == ()
    assert result.ledger == ()
    assert result.collection_assurance == 'unknown'
    assert json.loads((out / 'inputs.json').read_bytes())['files'] == []


@pytest.mark.skipif(os.name != 'nt', reason='Windows ACL integration')
def test_windows_snapshot_directories_have_owner_only_acl(api, sample):
    _, kwargs = sample
    out = api.prepare_snapshot_bundle((), **kwargs)
    for directory in (out, out / 'snapshots', out / 'documents'):
        assert_owner_only(directory)
    assert_owner_only(out / 'snapshot-bundle.json', directory=False)


def test_snapshot_child_directory_failure_stops_before_evidence_write(api, sample, monkeypatch):
    create = private_fs._create
    def fail_documents(target):
        if target.name == 'documents':
            raise OSError('injected')
        create(target)
    monkeypatch.setattr(private_fs, '_create', fail_documents)
    _, kwargs = sample
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle((), **kwargs)
    assert not any(path.is_file() for path in kwargs['destination'].rglob('*'))


@pytest.mark.parametrize('kind', ['file', 'parent'])
def test_snapshot_symlink_or_symlink_parent_is_rejected(api, sample, lab, kind):
    snapshots, kwargs = sample
    alias = lab / 'alias'
    try:
        alias.symlink_to(snapshots[0].path if kind == 'file' else lab, target_is_directory=kind == 'parent')
    except OSError:
        pytest.skip('Symlink creation privilege unavailable on this platform')
    path = alias if kind == 'file' else alias / snapshots[0].path.name
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle((replace(snapshots[0], path=path),), **kwargs)
    assert not kwargs['destination'].exists()


def test_output_hardlink_tampering_is_rejected(api, sample, lab):
    snapshots, kwargs = sample
    out = api.prepare_snapshot_bundle(snapshots, **kwargs)
    os.link(out / 'profile.json', lab / 'profile-alias.json')
    with pytest.raises(api.SnapshotBundleError):
        api.verify_snapshot_bundle(out)


@pytest.mark.parametrize('change', ['unknown_key', 'path_escape', 'wrong_kind', 'wrong_version', 'assurance'])
def test_manifest_cannot_expand_reader_scope(api, sample, change):
    snapshots, kwargs = sample
    out = api.prepare_snapshot_bundle(snapshots, **kwargs)
    path = out / 'snapshot-bundle.json'
    manifest = json.loads(path.read_bytes())
    if change == 'unknown_key':
        manifest['extra'] = True
    elif change == 'path_escape':
        manifest['snapshots'][0]['path'] = '../../PRIVATE_CANARY'
    elif change == 'wrong_kind':
        manifest['kind'] = 'attested'
    elif change == 'wrong_version':
        manifest['version'] = '99.0.0'
    else:
        manifest['scope']['collection_assurance'] = 'complete'
    path.write_bytes(json.dumps(manifest).encode())
    with pytest.raises(api.SnapshotBundleError) as caught:
        api.verify_snapshot_bundle(out)
    assert 'PRIVATE_CANARY' not in str(caught.value)


def test_equivalent_timezone_context_does_not_change_bytes(api, sample):
    snapshots, kwargs = sample
    context = json.loads(kwargs['context'])
    context['start'] = '2026-01-01T07:00:00+07:00'
    context['end'] = '2026-01-01T07:01:00+07:00'
    kwargs['context'] = json.dumps(context).encode()
    out = api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert (out / 'context.json').read_bytes() == kwargs['context']
    assert len(api.verify_snapshot_bundle(out).documents) == 2


def test_constructed_invalid_input_object_fails_sanitized(api, sample):
    _, kwargs = sample
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle((object.__new__(api.SnapshotFile),), **kwargs)
    assert not kwargs['destination'].exists()


def test_growing_sources_cannot_exceed_remaining_read_budget(api, sample, lab, monkeypatch):
    original, kwargs = sample
    raw = original[0].path.read_bytes()
    second_raw = raw + b'\n'
    second = lab / 'second.jsonl'
    original[0].path.write_bytes(b'')
    second.write_bytes(b'')
    inputs = (original[0], api.SnapshotFile(second, 'synthetic-two', hashlib.sha256(second_raw).hexdigest()))
    budget = len(raw) + len(second_raw) - 1
    monkeypatch.setattr(api, 'MAX_TOTAL_BYTES', budget)
    real_read = api.read_file
    limits = []

    def grown(path, limit):
        path.write_bytes(raw if path == original[0].path else second_raw)
        limits.append(limit)
        return real_read(path, limit)

    monkeypatch.setattr(api, 'read_file', grown)
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle(inputs, **kwargs)
    assert limits == [budget, budget - len(raw)]
    assert not kwargs['destination'].exists()


def test_snapshot_count_limit_before_read(api, sample):
    snapshots, kwargs = sample
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle(snapshots * 33, **kwargs)
    assert not kwargs['destination'].exists()


def test_large_source_rejected_before_content_read(api, sample):
    snapshots, kwargs = sample
    with snapshots[0].path.open('wb') as stream:
        stream.truncate(32 * 1024 * 1024 + 1)
    with pytest.raises(api.SnapshotBundleError):
        api.prepare_snapshot_bundle(snapshots, **kwargs)
    assert not kwargs['destination'].exists()


def test_inventory_stops_statting_files_at_limit(lab, monkeypatch):
    from aegis_verify.demo import _bundle_io
    from aegis_verify.intake import IntakeError

    directory = lab / 'documents'
    directory.mkdir()
    for number in range(150):
        (directory / f'synthetic-{number}.json').write_bytes(b'{}')
    real_check = _bundle_io.checked_file
    checked = []

    def tracked(path):
        checked.append(path)
        return real_check(path)

    monkeypatch.setattr(_bundle_io, 'checked_file', tracked)
    with pytest.raises(IntakeError) as caught:
        _bundle_io.inventory(lab)
    assert caught.value.code == 'resource_limit'
    assert len(checked) <= 139
