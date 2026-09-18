"""Caller review uses synthetic snapshots; no payload execution or lab access."""

import importlib
import json
from pathlib import Path
import tempfile

import pytest

from test_scn001_study_run import inputs, wire, sha, ROOT
from aegis_verify.demo.run import verify_run
from aegis_verify.demo.snapshot_bundle import SnapshotFile, prepare_snapshot_bundle, verify_snapshot_bundle
from aegis_verify.connectors.wazuh.manager_snapshot import ManagerSnapshotScope
from aegis_verify.validation import EvaluationContext, EvaluationProfile, evaluate_scenario
from aegis_verify.scenario_loader import parse_scenario_yaml


@pytest.fixture
def api():
    return importlib.import_module('aegis_verify.demo.collection_review')


@pytest.fixture
def bundle(inputs):
    checked = verify_run(**inputs)
    target = json.loads(inputs['study'])['target']
    records = []
    for name in ('sysmon1', 'powershell4104'):
        record = json.loads((ROOT / f'tests/fixtures/wazuh/windows-telemetry/{name}.synthetic.json').read_bytes())['_source']
        record['decoder'] = {'name': 'windows_eventchannel'}
        win = record['data']['win']
        win['system']['systemTime'] = '2026-01-01T00:00:10.223456789Z'
        if name == 'sysmon1':
            win['eventdata']['image'] = target['canonical_executable']
            win['eventdata']['commandLine'] = target['command_lines'][0]
        else:
            win['eventdata']['path'] = target['canonical_paths'][0]
            record['rule']['id'] = '91816'
        records.append(wire(record))
    with tempfile.TemporaryDirectory(prefix='aegis-synthetic-review-') as directory:
        source = Path(directory) / 'source.jsonl'
        source.write_bytes(b'\n'.join(records))
        scope = ManagerSnapshotScope('901', 'synthetic-endpoint', 'synthetic-env',
                                     checked.context.start.isoformat(), checked.context.end.isoformat(),
                                     '2026-01-01T00:03:00Z')
        yield prepare_snapshot_bundle((SnapshotFile(source, 'synthetic-review', sha(source.read_bytes())),),
                                      scope=scope, profile=inputs['profile'],
                                      context=wire(checked.context.model_dump(mode='json')),
                                      destination=Path(directory) / 'bundle')


def approval_for(request):
    # Explicit simulated operator action; production must never fill these flags.
    return dict(kind='scn001_collection_approval', version='0.1.0', request_sha256=sha(request),
                confirmed_by='synthetic-reviewer', reference='synthetic-collection-review',
                collected_at='2026-01-01T00:03:00Z', reviewed_at='2026-01-01T00:04:00Z',
                coverage_start='2026-01-01T00:00:00Z', coverage_end='2026-01-01T00:02:01Z',
                no_sampling_or_truncation=True, no_parse_errors_or_gaps=True, clocks_adequate=True,
                health_reference='synthetic-health', filter_reference='synthetic-filter',
                rotation_reference='synthetic-rotation', backlog_reference='synthetic-backlog',
                native_reference='synthetic-native-review', time_reference='synthetic-time')


def evaluate(inputs, bundle, context):
    events = tuple(d.telemetry.event for d in verify_snapshot_bundle(bundle).documents)
    return evaluate_scenario(parse_scenario_yaml(inputs['scenario'].decode(), source_name='synthetic'), events,
                             profile=EvaluationProfile.model_validate(json.loads(inputs['profile'])),
                             context=EvaluationContext.model_validate(json.loads(context)))


def test_approval_changes_only_collection_not_original_bytes_or_evidence(api, inputs, bundle):
    original = {p.relative_to(bundle): p.read_bytes() for p in bundle.rglob('*') if p.is_file()}
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    data = json.loads(request)
    assert data['kind'] == 'scn001_collection_request'
    assert data['run_id'] == 'synthetic-A'
    assert data['assertion_id'] == 'SCN-001-A03'
    assert 'no_sampling_or_truncation' not in data
    before = evaluate(inputs, bundle, (bundle / 'context.json').read_bytes())
    context = api.approve_collection_request(bundle, run_inputs=inputs, request=request, approval=wire(approval_for(request)))
    after = evaluate(inputs, bundle, context)
    assert before.final_status == 'Inconclusive'
    assert after.final_status == 'False negative'
    assert after.assertions[2].collection_assurance == 'caller-attested'
    assert after.evidence_index == before.evidence_index
    assert len(json.loads(context)['declarations']) == 1
    assert {p.relative_to(bundle): p.read_bytes() for p in bundle.rglob('*') if p.is_file()} == original


@pytest.mark.parametrize('field', ['no_sampling_or_truncation', 'no_parse_errors_or_gaps', 'clocks_adequate'])
@pytest.mark.parametrize('value', [False, None, 1, 'true'])
def test_no_implicit_confirmation(api, inputs, bundle, field, value):
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    approval = approval_for(request) | {field: value}
    with pytest.raises(api.CollectionReviewError):
        api.approve_collection_request(bundle, run_inputs=inputs, request=request, approval=wire(approval))


@pytest.mark.parametrize('field', list(approval_for(b'').keys()))
def test_every_approval_field_is_required(api, inputs, bundle, field):
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    approval = approval_for(request)
    del approval[field]
    with pytest.raises(api.CollectionReviewError):
        api.approve_collection_request(bundle, run_inputs=inputs, request=request, approval=wire(approval))


@pytest.mark.parametrize('field,value', [('request_sha256', '0' * 64), ('confirmed_by', ' '),
                                     ('native_reference', ''), ('extra', 'PRIVATE_CANARY'),
                                     ('coverage_start', '2026-01-01T00:00:00.123456790Z'),
                                     ('coverage_end', '2026-01-01T00:02:00.123456788Z')])
def test_invalid_or_stale_approval_is_sanitized(api, inputs, bundle, field, value):
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    with pytest.raises(api.CollectionReviewError) as caught:
        api.approve_collection_request(bundle, run_inputs=inputs, request=request,
                                       approval=wire(approval_for(request) | {field: value}))
    assert 'PRIVATE_CANARY' not in str(caught.value)


def test_request_tampering_rejected_even_if_operator_hash_matches(api, inputs, bundle):
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    changed = wire(json.loads(request) | {'event_set_fingerprint': '0' * 64})
    with pytest.raises(api.CollectionReviewError):
        api.approve_collection_request(bundle, run_inputs=inputs, request=changed, approval=wire(approval_for(changed)))


def test_valid_run_receipt_change_invalidates_prior_request(api, inputs, bundle):
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    inputs['receipt'] = wire(json.loads(inputs['receipt']) | {'before_reference': 'another-review'})
    with pytest.raises(api.CollectionReviewError):
        api.approve_collection_request(bundle, run_inputs=inputs, request=request, approval=wire(approval_for(request)))


@pytest.mark.parametrize('name', ['context.json', 'profile.json', 'ledger.json', 'snapshot-bundle.json'])
def test_bundle_mutation_invalidates_request(api, inputs, bundle, name):
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    path = bundle / name
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(api.CollectionReviewError):
        api.approve_collection_request(bundle, run_inputs=inputs, request=request, approval=wire(approval_for(request)))


@pytest.mark.parametrize('raw', [b'{}', b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'PRIVATE_CANARY', b' ' * 1048577],
                         ids=['empty', 'array', 'duplicate', 'nan', 'invalid', 'oversized'])
def test_malformed_approval_does_not_leak_input(api, inputs, bundle, raw):
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    with pytest.raises(api.CollectionReviewError) as caught:
        api.approve_collection_request(bundle, run_inputs=inputs, request=request, approval=raw)
    assert 'PRIVATE_CANARY' not in str(caught.value)


def repack(bundle, *, suffix, scope_changes=None, profile=None, context=None, raw=None):
    manifest = json.loads((bundle / 'snapshot-bundle.json').read_bytes())
    scope = ManagerSnapshotScope(**(manifest['scope'] | (scope_changes or {})))
    source = bundle.parent / (suffix + '.jsonl')
    source.write_bytes(raw if raw is not None else (bundle / manifest['snapshots'][0]['path']).read_bytes())
    return prepare_snapshot_bundle((SnapshotFile(source, 'synthetic-review', sha(source.read_bytes())),), scope=scope,
                                   profile=profile or (bundle / 'profile.json').read_bytes(),
                                   context=context or (bundle / 'context.json').read_bytes(),
                                   destination=bundle.parent / suffix)


@pytest.mark.parametrize('change', ['agent', 'host', 'context', 'profile'])
def test_independently_valid_transport_must_match_reviewed_run(api, inputs, bundle, change):
    options = {}
    if change in ('agent', 'host'):
        options['scope_changes'] = {('agent_id' if change == 'agent' else 'hostname'): 'different'}
    elif change == 'context':
        options['context'] = wire(json.loads((bundle / 'context.json').read_bytes()) | {'run_id': 'different'})
    else:
        options['profile'] = wire(json.loads(inputs['profile']) | {'profile_id': 'different'})
    other = repack(bundle, suffix='different', **options)
    verify_snapshot_bundle(other)
    with pytest.raises(api.CollectionReviewError):
        api.prepare_collection_request(other, run_inputs=inputs)


def test_new_valid_snapshot_invalidates_old_request_even_with_same_canonical_events(api, inputs, bundle):
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    other = repack(bundle, suffix='new-source', raw=(bundle / json.loads((bundle / 'snapshot-bundle.json').read_bytes())['snapshots'][0]['path']).read_bytes() + b'\n')
    verify_snapshot_bundle(other)
    with pytest.raises(api.CollectionReviewError):
        api.approve_collection_request(other, run_inputs=inputs, request=request, approval=wire(approval_for(request)))


def test_empty_snapshot_attestation_cannot_invent_telemetry_or_pass(api, inputs, bundle):
    empty = repack(bundle, suffix='empty-snapshot', raw=b'')
    request = api.prepare_collection_request(empty, run_inputs=inputs)
    context = api.approve_collection_request(empty, run_inputs=inputs, request=request, approval=wire(approval_for(request)))
    result = evaluate(inputs, empty, context)
    assert result.final_status == 'Missing telemetry'
    assert result.evidence_index == ()


@pytest.mark.parametrize('which', ['study', 'execution', 'receipt'])
def test_cannot_bypass_run_verification(api, inputs, bundle, which):
    inputs[which] = b'{}'
    with pytest.raises(api.CollectionReviewError):
        api.prepare_collection_request(bundle, run_inputs=inputs)


def test_explicit_approval_cannot_supply_verdict(api, inputs, bundle):
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    with pytest.raises(api.CollectionReviewError):
        api.approve_collection_request(bundle, run_inputs=inputs, request=request,
                                       approval=wire(approval_for(request) | {'final_status': 'Detected'}))


@pytest.mark.parametrize('fields', [
    {'collected_at': '2026-01-01T00:01:00Z'},
    {'reviewed_at': '2026-01-01T00:02:30Z'},
    {'collected_at': None},
])
def test_collection_and_review_times_must_follow_whole_coverage(api, inputs, bundle, fields):
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    with pytest.raises(api.CollectionReviewError):
        api.approve_collection_request(bundle, run_inputs=inputs, request=request,
                                       approval=wire(approval_for(request) | fields))


def test_snapshot_captured_before_the_window_closed_cannot_be_attested(api, inputs, bundle):
    """A snapshot declared as taken mid-window cannot cover that window."""
    early = repack(bundle, suffix='early-snapshot', scope_changes={'ingested_at': '2026-01-01T00:00:30Z'})
    verify_snapshot_bundle(early)
    with pytest.raises(api.CollectionReviewError):
        api.prepare_collection_request(early, run_inputs=inputs)


def test_snapshot_captured_exactly_at_window_end_is_still_reviewable(api, inputs, bundle):
    """The gate rules out the provable case only; it never asserts completeness."""
    boundary = repack(bundle, suffix='boundary-snapshot',
                      scope_changes={'ingested_at': '2026-01-01T00:02:00.123456789Z'})
    assert api.prepare_collection_request(boundary, run_inputs=inputs)


def test_approval_cannot_be_moved_to_another_snapshot_of_the_same_window(api, inputs, bundle):
    """Same canonical events, different declared capture: the approval must not carry over."""
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    approval = wire(approval_for(request))
    other = repack(bundle, suffix='later-snapshot', scope_changes={'ingested_at': '2026-01-01T00:05:00Z'})
    verify_snapshot_bundle(other)
    with pytest.raises(api.CollectionReviewError):
        api.approve_collection_request(other, run_inputs=inputs, request=request, approval=approval)


def test_operator_cannot_collect_before_the_snapshot_was_captured(api, inputs, bundle):
    """collected_at earlier than the declared capture is incoherent and refused."""
    request = api.prepare_collection_request(bundle, run_inputs=inputs)
    approval = approval_for(request) | {'collected_at': '2026-01-01T00:02:30Z',
                                        'reviewed_at': '2026-01-01T00:02:40Z'}
    with pytest.raises(api.CollectionReviewError):
        api.approve_collection_request(bundle, run_inputs=inputs, request=request, approval=wire(approval))
