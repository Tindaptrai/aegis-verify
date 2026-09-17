"""Synthetic native review declarations; never execute or read raw lab data."""

import importlib
import json

import pytest

from test_scn001_study_run import inputs, wire, sha
from test_scn001_collection_review import bundle, repack, evaluate
from aegis_verify.demo.collection_review import prepare_collection_request
from aegis_verify.demo.snapshot_bundle import verify_snapshot_bundle


@pytest.fixture
def api():
    return importlib.import_module('aegis_verify.demo.run_binding')


def records(bundle):
    manifest = json.loads((bundle / 'snapshot-bundle.json').read_bytes())
    return [json.loads(line) for line in (bundle / manifest['snapshots'][0]['path']).read_bytes().splitlines()]


def changed_bundle(bundle, values):
    return repack(bundle, suffix='changed', raw=b'\n'.join(wire(v) for v in values))


def native(inputs, bundle):
    docs = verify_snapshot_bundle(bundle).documents
    by_kind = {d.parser: d.telemetry.event.event_id for d in docs}
    return dict(kind='scn001_native_review', version='0.1.0',
                request_sha256=sha(prepare_collection_request(bundle, run_inputs=inputs)),
                confirmed_by='synthetic-reviewer', reference='synthetic-native-records',
                reviewed_at='2026-01-01T00:04:00Z',
                payload_path=r'C:\Synthetic\AEGIS\lab_update.ps1',
                payload_sha256=sha(b"Write-Output 'AEGIS_SAFE_DEMO_V1'\nWrite-Output ('AEGIS_PID=' + $PID)\n"),
                full_script_reviewed=True, records=[
                    dict(evidence_id=by_kind['wazuh-sysmon1-v1'], provider='Microsoft-Windows-Sysmon', hostname='synthetic-endpoint',
                         windows_record_id='101', event_time='2026-01-01T00:00:10.223456789Z', process_id=4242,
                         process_guid='{00000000-0000-0000-0000-000000000001}', script_block_id=None,
                         parent_process_id=4000),
                    dict(evidence_id=by_kind['wazuh-powershell4104-v1'], provider='Microsoft-Windows-PowerShell', hostname='synthetic-endpoint',
                         windows_record_id='102', event_time='2026-01-01T00:00:10.223456789Z', process_id=4242,
                         process_guid=None, script_block_id='00000000-0000-0000-0000-000000000003'),
                ])


def test_no_native_confirmation_is_unknown_not_detection_verdict(api, inputs, bundle):
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs))
    assert result['status'] == 'unknown'
    assert 'native_review_missing' in result['reasons']
    assert len(result['evidence']) == 2
    assert 'final_status' not in result
    for item in result['evidence']:
        assert item['event_id'].startswith('wazuh:evidence-v1:')
        assert item['raw_event_ref'].endswith('#record=1')
        assert len(item['raw_event_hash']) == 64


def test_exact_native_review_is_caller_reviewed_never_lab_verdict(api, inputs, bundle):
    original = (bundle / 'context.json').read_bytes()
    receipt = native(inputs, bundle)
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'caller_reviewed'
    assert result['reasons'] == []
    assert result['native_review_sha256'] == sha(wire(receipt))
    assert (bundle / 'context.json').read_bytes() == original
    assert evaluate(inputs, bundle, original).final_status == 'Inconclusive'


@pytest.mark.parametrize('index', [0, 1])
@pytest.mark.parametrize('pid,status,reason', [('9999', 'conflict', 'child_pid_mismatch'),
                                            (None, 'unknown', 'missing_binding_metadata')])
def test_pid_cannot_be_guessed_from_manifest(api, inputs, bundle, index, pid, status, reason):
    values = records(bundle)
    parent = values[index]['data']['win']['eventdata' if index == 0 else 'system']
    parent['processId' if index == 0 else 'processID'] = pid
    other = changed_bundle(bundle, values)
    result = json.loads(api.review_run_binding(other, run_inputs=inputs))
    assert result['status'] == status
    assert reason in result['reasons']


@pytest.mark.parametrize('index,key,parent', [(0, 'processGuid', 'eventdata'), (0, 'eventRecordID', 'system'),
                                           (0, 'parentProcessId', 'eventdata'), (1, 'scriptBlockId', 'eventdata'),
                                           (1, 'eventRecordID', 'system')])
def test_missing_provenance_cannot_be_repaired_by_native_receipt(api, inputs, bundle, index, key, parent):
    values = records(bundle)
    del values[index]['data']['win'][parent][key]
    other = changed_bundle(bundle, values)
    result = json.loads(api.review_run_binding(other, run_inputs=inputs, native_review=wire(native(inputs, other))))
    assert result['status'] == 'unknown'
    assert 'missing_binding_metadata' in result['reasons']


@pytest.mark.parametrize('index', [0, 1])
def test_multiple_candidates_conflict_without_selecting_favorable_record(api, inputs, bundle, index):
    values = records(bundle)
    extra = json.loads(wire(values[index]))
    extra['id'] += '-another'
    extra['data']['win']['system']['eventRecordID'] = '999'
    values.append(extra)
    result = json.loads(api.review_run_binding(changed_bundle(bundle, values), run_inputs=inputs))
    assert result['status'] == 'conflict'
    assert 'multiple_candidates' in result['reasons']
    assert len(result['evidence']) == 3


@pytest.mark.parametrize('index,field,value,parent,reason', [
    (0, 'parentProcessId', '9999', 'eventdata', 'parent_pid_mismatch'),
    (0, 'systemTime', '2026-01-01T00:00:01Z', 'system', 'outside_execution_interval'),
    (1, 'systemTime', '2026-01-01T00:01:00Z', 'system', 'outside_execution_interval'),
    (1, 'path', r'C:\\Synthetic\\AEGIS\\maintenance_check.ps1', 'eventdata', 'payload_variant_mismatch'),
    (0, 'commandLine', 'not-the-reviewed-command', 'eventdata', 'payload_variant_mismatch'),
])
def test_conflicting_execution_metadata(api, inputs, bundle, index, field, value, parent, reason):
    values = records(bundle)
    values[index]['data']['win'][parent][field] = value
    result = json.loads(api.review_run_binding(changed_bundle(bundle, values), run_inputs=inputs))
    assert result['status'] == 'conflict'
    assert reason in result['reasons']


def test_missing_match_field_retains_unknown_candidate(api, inputs, bundle):
    values = records(bundle)
    del values[0]['data']['win']['eventdata']['commandLine']
    result = json.loads(api.review_run_binding(changed_bundle(bundle, values), run_inputs=inputs))
    assert result['status'] == 'unknown'
    assert len(result['evidence']) == 2


def test_empty_bundle_is_unknown_with_no_fabricated_evidence(api, inputs, bundle):
    result = json.loads(api.review_run_binding(changed_bundle(bundle, []), run_inputs=inputs))
    assert result['status'] == 'unknown'
    assert 'missing_telemetry' in result['reasons']
    assert result['evidence'] == []


@pytest.mark.parametrize('field,value', [('process_id', 9999), ('process_guid', 'different'),
                                     ('windows_record_id', '999'), ('event_time', '2026-01-01T00:00:10.223456790Z'),
                                     ('evidence_id', 'different-evidence'), ('provider', 'different-provider'),
                                     ('hostname', 'different-host')])
def test_native_metadata_mismatch_is_conflict(api, inputs, bundle, field, value):
    receipt = native(inputs, bundle)
    receipt['records'][0][field] = value
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'conflict'
    assert 'native_metadata_mismatch' in result['reasons']


@pytest.mark.parametrize('field,value', [('payload_path', 'different'), ('payload_sha256', '0' * 64)])
def test_native_payload_review_cannot_target_other_payload(api, inputs, bundle, field, value):
    receipt = native(inputs, bundle) | {field: value}
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'conflict'


def test_unconfirmed_content_review_stays_unknown(api, inputs, bundle):
    receipt = native(inputs, bundle) | {'full_script_reviewed': False}
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'unknown'


@pytest.mark.parametrize('field,value', [('request_sha256', '0' * 64), ('full_script_reviewed', 1),
                                     ('confirmed_by', ' '), ('records', []), ('extra', 'PRIVATE_CANARY')])
def test_invalid_or_stale_native_review_is_input_error(api, inputs, bundle, field, value):
    with pytest.raises(api.RunBindingError) as caught:
        api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(native(inputs, bundle) | {field: value}))
    assert 'PRIVATE_CANARY' not in str(caught.value)


def test_unrelated_definite_nonmatch_not_a_launch_conflict(api, inputs, bundle):
    values = records(bundle)
    extra = json.loads(wire(values[0]))
    extra['id'] += '-unrelated'
    extra['data']['win']['eventdata']['commandLine'] = 'synthetic-unrelated'
    extra['data']['win']['eventdata']['processId'] = '8888'
    values.append(extra)
    other = changed_bundle(bundle, values)
    result = json.loads(api.review_run_binding(other, run_inputs=inputs))
    assert result['status'] == 'unknown'
    assert result['reasons'] == ['native_review_missing']
    assert len(result['evidence']) == 2
    assert len(verify_snapshot_bundle(other).documents) == 3


def test_conflict_takes_precedence_over_missing_metadata(api, inputs, bundle):
    values = records(bundle)
    values[0]['data']['win']['eventdata']['processId'] = '9999'
    del values[1]['data']['win']['system']['processID']
    result = json.loads(api.review_run_binding(changed_bundle(bundle, values), run_inputs=inputs))
    assert result['status'] == 'conflict'
    assert 'missing_binding_metadata' in result['reasons']
    assert 'child_pid_mismatch' in result['reasons']


@pytest.mark.parametrize('time', ['2026-01-01T00:00:10.123456788Z', '2026-01-01T00:00:11.123456790Z'])
def test_execution_interval_is_nanosecond_exact(api, inputs, bundle, time):
    values = records(bundle)
    values[0]['data']['win']['system']['systemTime'] = time
    result = json.loads(api.review_run_binding(changed_bundle(bundle, values), run_inputs=inputs))
    assert result['status'] == 'conflict'


def test_record_receipt_order_is_not_identity(api, inputs, bundle):
    receipt = native(inputs, bundle)
    receipt['records'].reverse()
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'caller_reviewed'


def test_duplicate_native_evidence_cannot_replace_missing_peer(api, inputs, bundle):
    receipt = native(inputs, bundle)
    receipt['records'][1] = receipt['records'][0]
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'conflict'


@pytest.mark.parametrize('field', ['kind', 'version', 'request_sha256', 'confirmed_by', 'reference',
                                 'reviewed_at', 'payload_path', 'payload_sha256', 'full_script_reviewed', 'records'])
def test_native_review_requires_all_fields(api, inputs, bundle, field):
    receipt = native(inputs, bundle)
    del receipt[field]
    with pytest.raises(api.RunBindingError):
        api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt))


@pytest.mark.parametrize('raw', [b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'private-canary', b' ' * 1048577],
                         ids=['array', 'duplicate', 'nan', 'invalid', 'oversized'])
def test_bad_native_json_is_sanitized(api, inputs, bundle, raw):
    with pytest.raises(api.RunBindingError) as caught:
        api.review_run_binding(bundle, run_inputs=inputs, native_review=raw)
    assert 'private-canary' not in str(caught.value)


def test_blank_source_provenance_stays_unknown(api, inputs, bundle):
    values = records(bundle)
    values[0]['data']['win']['eventdata']['processGuid'] = ' '
    other = changed_bundle(bundle, values)
    result = json.loads(api.review_run_binding(other, run_inputs=inputs, native_review=wire(native(inputs, other))))
    assert result['status'] == 'unknown'


@pytest.mark.parametrize('label', ['B', 'C', 'Rehearsal'])
def test_renamed_runs_bind_same_study_without_relabeling(api, inputs, bundle, label):
    from aegis_verify.demo.run import verify_run

    study = json.loads(inputs['study'])
    revision = 'fixed' if label == 'C' else 'baseline'
    rule_hash = study['pins'][revision]
    for name in ('execution_start', 'execution_launched', 'execution'):
        value = json.loads(inputs[name])
        value.update(run_label=label, run_id='synthetic-' + label, applied_rule_revision_declared=revision,
                     applied_rule_sha256_declared=rule_hash,
                     payload_path=value['payload_path'].replace('lab_update.ps1', 'maintenance_check.ps1'),
                     arguments=value['arguments'].replace('lab_update.ps1', 'maintenance_check.ps1'))
        inputs[name] = wire(value)
    inputs['receipt'] = wire(json.loads(inputs['receipt']) | dict(run_id='synthetic-' + label,
        execution_sha256=sha(inputs['execution']), before_rule_sha256=rule_hash, after_rule_sha256=rule_hash))
    values = records(bundle)
    values[0]['data']['win']['eventdata']['commandLine'] = study['target']['command_lines'][1]
    values[1]['data']['win']['eventdata']['path'] = study['target']['canonical_paths'][1]
    other = repack(bundle, suffix='renamed', raw=b'\n'.join(wire(v) for v in values),
                   context=wire(verify_run(**inputs).context.model_dump(mode='json')))
    receipt = native(inputs, other)
    receipt['payload_path'] = r'C:\Synthetic\AEGIS\maintenance_check.ps1'
    result = json.loads(api.review_run_binding(other, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'caller_reviewed'
    assert result['run_id'] == 'synthetic-' + label


def test_omitted_parent_pid_is_recorded_not_assumed(api, inputs, bundle):
    """A field the operator did not corroborate must never read as a complete binding."""
    receipt = native(inputs, bundle)
    receipt['records'][0].pop('parent_process_id')
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'unknown'
    assert 'native_parent_unconfirmed' in result['reasons']


def test_wrong_parent_pid_is_a_conflict(api, inputs, bundle):
    receipt = native(inputs, bundle)
    receipt['records'][0]['parent_process_id'] = 4001
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'conflict'
    assert 'native_metadata_mismatch' in result['reasons']


def test_script_record_must_not_declare_a_parent_pid(api, inputs, bundle):
    receipt = native(inputs, bundle)
    receipt['records'][1]['parent_process_id'] = 4000
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'conflict'


def test_binding_states_both_sides_are_caller_declared(api, inputs, bundle):
    receipt = native(inputs, bundle)
    result = json.loads(api.review_run_binding(bundle, run_inputs=inputs, native_review=wire(receipt)))
    assert result['status'] == 'caller_reviewed'
    assert result['both_sides_caller_declared'] is True
