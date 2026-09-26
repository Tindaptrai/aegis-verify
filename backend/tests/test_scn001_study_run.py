"""Synthetic study/runner metadata only: no payload or remote execution."""

import hashlib
import importlib
import importlib.util
import json
from pathlib import Path

import pytest

from aegis_verify.demo._study_contracts import wire_text
from aegis_verify.scenario_loader import parse_scenario_yaml
from aegis_verify.validation import evaluate_scenario, scenario_fingerprint

ROOT = Path(__file__).resolve().parents[2]


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def api():
    return importlib.import_module('aegis_verify.demo.run')


@pytest.fixture
def inputs(tmp_path):
    spec = importlib.util.spec_from_file_location('synthetic_study_kit', ROOT / 'scripts/prepare_scn001_kit.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    directory = r'C:\Synthetic\AEGIS'
    kit_dir = tmp_path / 'synthetic-kit'
    builder.prepare_kit(output_dir=kit_dir, lab_directory=directory, target_host='synthetic-endpoint',
                        rule_id=119901, parent_sid=91816, occupied_ids=frozenset(),
                        field_profile='wazuh-eventchannel-4.14.4-lf-v1')
    kit_raw = (kit_dir / 'kit.json').read_bytes()
    kit = json.loads(kit_raw)
    artifacts = {name: (kit_dir / name).read_bytes() for name in kit['artifact_sha256']}
    scenario_raw = (ROOT / 'scenarios/SCN-001-powershell-execution.yaml').read_bytes()
    scenario = parse_scenario_yaml(scenario_raw.decode(), source_name='synthetic')
    native_paths = [directory + '\\' + name for name in ('lab_update.ps1', 'maintenance_check.ps1')]
    native_executable = 'C:\\Synthetic\\powershell.exe'
    native_commands = ['synthetic-powershell -File "' + p + '"' for p in native_paths]
    # Wazuh 4.14.4 delivers the JSON-escaped form of the native value in every
    # decoded eventdata string, measured against real telemetry on 2026-09-17.
    # Build every canonical value through one helper so they cannot drift apart.
    paths = [wire_text(p) for p in native_paths]
    commands = [wire_text(c) for c in native_commands]
    canonical_executable = wire_text(native_executable)
    base_scope = [{'field': 'hostname', 'op': 'eq', 'binding': 'target_host'},
                  {'field': 'asset_id', 'op': 'eq', 'binding': 'target_agent'}]
    sysmon_scope = base_scope + [{'field': 'event_provider', 'op': 'eq', 'value': 'Microsoft-Windows-Sysmon'}]
    ps_scope = base_scope + [{'field': 'event_provider', 'op': 'eq', 'value': 'Microsoft-Windows-PowerShell'}]
    profile = dict(profile_schema_version='0.1.0', profile_id='synthetic-scn001-study', profile_version='0.1.0',
                   scenario_id='SCN-001', scenario_version='0.1.0', scenario_fingerprint=scenario_fingerprint(scenario),
                   rules=[
                       dict(assertion_id='SCN-001-A01', role='telemetry', capability='supported', source_type='wazuh',
                            scope=sysmon_scope, match=[{'field': 'process_name', 'op': 'eq', 'value': canonical_executable},
                                                     {'field': 'command_line', 'op': 'in', 'values': commands}]),
                       dict(assertion_id='SCN-001-A02', role='telemetry', capability='supported', source_type='wazuh',
                            scope=ps_scope, match=[{'field': 'file_path', 'op': 'in', 'values': paths}]),
                       dict(assertion_id='SCN-001-A03', role='detection', capability='supported', source_type='wazuh',
                            scope=ps_scope, match=[{'field': 'file_path', 'op': 'in', 'values': paths},
                                                  {'field': 'rule_id', 'op': 'exists'},
                                                  {'field': 'rule_id', 'op': 'eq', 'value': '119901'}],
                            correlation=dict(anchor_assertion_id='SCN-001-A01',
                                             join_pairs=[dict(target_field=k, anchor_field=k) for k in ('hostname', 'asset_id', 'process_id')],
                                             min_delta_ns=-5000000000, max_delta_ns=15000000000)),
                   ])
    profile_raw = wire(profile)
    study = dict(kind='scn001_study', version='0.1.0', study_id='synthetic-study',
                 pins=dict(scenario=sha(scenario_raw), profile=sha(profile_raw), kit=sha(kit_raw),
                           runner=sha(artifacts['Invoke-SafeDemo.ps1']), payload=sha(artifacts['lab_update.ps1']),
                           baseline=sha(artifacts['baseline.xml']), fixed=sha(artifacts['fixed.xml']),
                           behavioral=sha(artifacts['behavioral.xml'])),
                 target=dict(environment_id='synthetic-env', hostname='synthetic-endpoint', agent_id='901',
                             account='SYNTHETIC\\operator', elevated=True, executable=native_executable,
                             canonical_executable=canonical_executable, collection_mode='direct',
                             native_directory=directory, canonical_paths=paths, command_lines=commands,
                             rule_id=119901, parent_sid=91816, field_profile='wazuh-eventchannel-4.14.4-lf-v1'),
                 collection_reference='synthetic-collection-checklist', time_reference='synthetic-clock-review')
    study_raw = wire(study)
    start = dict(kind='safe_demo_execution', execution_manifest_version='0.1.0', run_id='synthetic-A', run_label='A',
                 target_host='synthetic-endpoint', scenario_id='SCN-001', scenario_version='0.1.0',
                 payload_sha256=kit['payload_sha256'], payload_path=native_paths[0], rule_id=119901, parent_sid=91816,
                 applied_rule_revision_declared='baseline', applied_rule_sha256_declared=study['pins']['baseline'],
                 rule_state_verified_remotely=False, runner_pid=4000, child_pid=None,
                 executable=r'C:\Synthetic\powershell.exe', arguments='-NoLogo -NoProfile -NonInteractive -File "' + native_paths[0] + '"',
                 window_start_utc='2026-01-01T00:00:00.123456789Z', window_planned_end_utc='2026-01-01T00:02:00.123456789Z',
                 launch_utc=None, exit_observed_utc=None, window_observed_end_utc=None, exit_code=None,
                 timed_out=False, status='started', failure_code=None)
    launched = start | dict(child_pid=4242, launch_utc='2026-01-01T00:00:10.123456789Z')
    final = launched | dict(exit_observed_utc='2026-01-01T00:00:11.123456789Z', exit_code=0, status='executed',
                            window_observed_end_utc='2026-01-01T00:02:00.373456789Z', elapsed_seconds=120.25)
    receipt = dict(kind='scn001_rule_receipt', version='0.1.0', run_id='synthetic-A', study_sha256=sha(study_raw),
                   execution_sha256=sha(wire(final)), account='SYNTHETIC\\operator', elevated=True,
                   before_rule_sha256=study['pins']['baseline'], after_rule_sha256=study['pins']['baseline'],
                   before_utc='2026-01-01T00:00:00Z', after_utc='2026-01-01T00:02:01Z',
                   confirmed_by='synthetic-operator', before_reference='synthetic-before', after_reference='synthetic-after')
    return dict(study=study_raw, study_sha256=sha(study_raw), scenario=scenario_raw, profile=profile_raw,
                kit=kit_raw, artifacts=artifacts, execution_start=wire(start), execution_launched=wire(launched),
                execution=wire(final), stdout=b'AEGIS_SAFE_DEMO_V1\r\nAEGIS_PID=4242\r\n', stderr=b'', receipt=wire(receipt))


def update_final(inputs, **fields):
    final = json.loads(inputs['execution']) | fields
    inputs['execution'] = wire(final)
    receipt = json.loads(inputs['receipt']) | {'execution_sha256': sha(inputs['execution'])}
    inputs['receipt'] = wire(receipt)


def test_valid_run_keeps_exact_window_and_unknown_context(api, inputs):
    checked = api.verify_run(**inputs)
    assert checked.child_pid == 4242
    assert checked.run_label == 'A'
    assert checked.context.start.isoformat() == '2026-01-01T00:00:00.123456789Z'
    assert checked.context.end.difference_ns(checked.context.start) == 120000000000
    assert checked.context.declarations == ()
    assert {b.name: b.value for b in checked.context.bindings} == {'target_host': 'synthetic-endpoint', 'target_agent': '901'}
    assert checked.input_sha256['execution.json'] == sha(inputs['execution'])
    from aegis_verify.validation import EvaluationProfile
    result = evaluate_scenario(parse_scenario_yaml(inputs['scenario'].decode(), source_name='synthetic'), (),
                               profile=EvaluationProfile.model_validate(json.loads(inputs['profile'])), context=checked.context)
    assert result.final_status == 'Missing telemetry'
    assert all(a.outcome == 'missing_telemetry' for a in result.assertions)


@pytest.mark.parametrize('field,value', [
    ('status', 'failed'), ('timed_out', True), ('exit_code', 1), ('exit_code', False),
    ('child_pid', None), ('child_pid', True), ('child_pid', 0), ('child_pid', 4243),
    ('failure_code', 'AEGIS_FAILURE'), ('rule_state_verified_remotely', True),
    ('run_label', 'B'), ('target_host', 'different'), ('runner_pid', True),
    ('elapsed_seconds', -1), ('elapsed_seconds', '120.25'), ('elapsed_seconds', True),
    ('elapsed_seconds', float('nan')), ('elapsed_seconds', float('inf')),
    ('window_observed_end_utc', '2026-01-01T00:02:00.123456788Z'),
    ('exit_observed_utc', '2026-01-01T00:03:00Z'), ('exit_observed_utc', '2026-01-01T00:00:01Z'),
    ('extra', 'PRIVATE_CANARY'),
])
def test_bad_final_metadata_fails_even_with_updated_receipt_hash(api, inputs, field, value):
    update_final(inputs, **{field: value})
    with pytest.raises(api.StudyRunError) as caught:
        api.verify_run(**inputs)
    assert 'PRIVATE_CANARY' not in str(caught.value)


@pytest.mark.parametrize('which', ['execution_start', 'execution_launched', 'execution'])
def test_missing_manifest_is_not_recreated(api, inputs, which):
    inputs[which] = b''
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('which', ['scenario', 'profile', 'kit', 'study'])
def test_pinned_input_bytes_cannot_change(api, inputs, which):
    inputs[which] += b' '
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('field,value', [('account', 'different'), ('elevated', False), ('elevated', 1),
                                      ('execution_sha256', '0' * 64), ('study_sha256', '0' * 64),
                                      ('before_rule_sha256', '0' * 64), ('after_rule_sha256', '0' * 64),
                                      ('before_utc', '2026-01-01T00:00:01Z'), ('after_utc', '2026-01-01T00:02:00Z'),
                                      ('confirmed_by', ''), ('before_reference', ''), ('extra', True)])
def test_stale_or_incomplete_operator_receipt_rejected(api, inputs, field, value):
    inputs['receipt'] = wire(json.loads(inputs['receipt']) | {field: value})
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('name', ['Invoke-SafeDemo.ps1', 'lab_update.ps1', 'maintenance_check.ps1', 'baseline.xml', 'fixed.xml', 'behavioral.xml'])
def test_artifact_tamper_never_passes(api, inputs, name):
    inputs['artifacts'][name] += b' '
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('which,raw', [('stdout', b'AEGIS_SAFE_DEMO_V1\nAEGIS_PID=9999\n'), ('stderr', b'error'),
                                   ('stdout', b'AEGIS_SAFE_DEMO_V1\n'), ('stdout', b'')])
def test_stdio_must_match_child(api, inputs, which, raw):
    inputs[which] = raw
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


def test_window_one_nanosecond_drift_rejected_in_all_manifests(api, inputs):
    for name in ('execution_start', 'execution_launched', 'execution'):
        inputs[name] = wire(json.loads(inputs[name]) | {'window_planned_end_utc': '2026-01-01T00:02:00.123456790Z'})
    update_final(inputs)
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('label', ['B', 'C', 'Rehearsal'])
def test_labels_have_correct_payload_revision_and_fixed_bindings(api, inputs, label):
    original = api.verify_run(**inputs)
    study = json.loads(inputs['study'])
    revision = 'behavioral' if label == 'C' else 'baseline'
    rule_hash = study['pins'][revision]
    for name in ('execution_start', 'execution_launched', 'execution'):
        obj = json.loads(inputs[name])
        obj.update(run_label=label, run_id='synthetic-' + label, applied_rule_revision_declared=revision,
                   applied_rule_sha256_declared=rule_hash,
                   payload_path=obj['payload_path'].replace('lab_update.ps1', 'maintenance_check.ps1'),
                   arguments=obj['arguments'].replace('lab_update.ps1', 'maintenance_check.ps1'))
        inputs[name] = wire(obj)
    receipt = json.loads(inputs['receipt']) | dict(run_id='synthetic-' + label, execution_sha256=sha(inputs['execution']),
                                                   before_rule_sha256=rule_hash, after_rule_sha256=rule_hash)
    inputs['receipt'] = wire(receipt)
    checked = api.verify_run(**inputs)
    assert checked.run_label == label
    assert checked.context.bindings == original.context.bindings
    assert checked.context.declarations == ()


@pytest.mark.parametrize('part', ['scope', 'match', 'correlation'])
def test_profile_semantics_cannot_drift_even_with_updated_hash_pin(api, inputs, part):
    profile = json.loads(inputs['profile'])
    if part == 'scope':
        profile['rules'][0]['scope'].pop()
    elif part == 'match':
        profile['rules'][1]['match'][0]['values'] = ['wrong-path']
    else:
        profile['rules'][2]['correlation']['max_delta_ns'] += 1
    inputs['profile'] = wire(profile)
    study = json.loads(inputs['study'])
    study['pins']['profile'] = sha(inputs['profile'])
    inputs['study'] = wire(study)
    inputs['study_sha256'] = sha(inputs['study'])
    inputs['receipt'] = wire(json.loads(inputs['receipt']) | {'study_sha256': inputs['study_sha256']})
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


def repin_study(inputs, study):
    inputs['study'] = wire(study)
    inputs['study_sha256'] = sha(inputs['study'])
    inputs['receipt'] = wire(json.loads(inputs['receipt']) | {'study_sha256': inputs['study_sha256']})


def test_native_and_canonical_executable_are_separately_reviewed(api, inputs):
    study = json.loads(inputs['study'])
    canonical = study['target']['executable'].replace('\\', '\\\\')
    study['target']['canonical_executable'] = canonical
    profile = json.loads(inputs['profile'])
    profile['rules'][0]['match'][0]['value'] = canonical
    inputs['profile'] = wire(profile)
    study['pins']['profile'] = sha(inputs['profile'])
    repin_study(inputs, study)
    checked = api.verify_run(**inputs)
    assert checked.child_pid == 4242
    assert json.loads(inputs['execution'])['executable'] != canonical


@pytest.mark.parametrize('field,value', [('collection_mode', 'forwarded'), ('elevated', 1),
                                      ('canonical_paths', ['same', 'same']), ('command_lines', ['same', 'same']),
                                      ('agent_id', ''), ('account', ''), ('rule_id', True),
                                      ('parent_sid', 119901), ('field_profile', 'unknown'), ('extra', True)])
def test_bad_study_target_rejected_after_repin(api, inputs, field, value):
    study = json.loads(inputs['study'])
    study['target'][field] = value
    repin_study(inputs, study)
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('name', ['execution_start', 'execution_launched', 'execution'])
def test_duplicate_keys_and_nested_data_rejected(api, inputs, name):
    inputs[name] = b'{"run_id":"a","run_id":"b"}'
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


def test_unreviewed_payload_rejected_even_if_all_hashes_updated(api, inputs):
    study, kit = json.loads(inputs['study']), json.loads(inputs['kit'])
    raw = b'Write-Output "synthetic different behavior"\n'
    for name in ('lab_update.ps1', 'maintenance_check.ps1'):
        inputs['artifacts'][name] = raw
        kit['artifact_sha256'][name] = sha(raw)
    kit['payload_sha256'] = sha(raw)
    inputs['kit'] = wire(kit)
    study['pins']['kit'], study['pins']['payload'] = sha(inputs['kit']), sha(raw)
    repin_study(inputs, study)
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('token', [b'1e999999999999999999999', b'0.1e-999999999999999999999', b'1.' + b'0' * 128])
def test_unrepresentable_or_overlong_decimal_is_sanitized(api, inputs, token):
    raw = inputs['execution'].replace(b'120.25', token)
    assert raw != inputs['execution']
    inputs['execution'] = raw
    inputs['receipt'] = wire(json.loads(inputs['receipt']) | {'execution_sha256': sha(raw)})
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('stage,field,value', [('execution_start', 'child_pid', 4242),
                                           ('execution_start', 'launch_utc', '2026-01-01T00:00:10Z'),
                                           ('execution_launched', 'exit_code', 0),
                                           ('execution_launched', 'child_pid', 4000),
                                           ('execution_launched', 'runner_pid', 4001),
                                           ('execution_start', 'runner_pid', 0)])
def test_stage_specific_fields_cannot_claim_later_progress(api, inputs, stage, field, value):
    inputs[stage] = wire(json.loads(inputs[stage]) | {field: value})
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('change', ['missing', 'extra'])
def test_closed_artifact_inventory(api, inputs, change):
    if change == 'missing':
        del inputs['artifacts']['logtest-cases/catalog.json']
    else:
        inputs['artifacts']['../PRIVATE_CANARY'] = b'not read from disk'
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('detected', [False, True])
def test_checked_context_with_real_parsers_preserves_unknown_detection_semantics(api, inputs, detected):
    from aegis_verify.connectors.wazuh.manager_snapshot import ManagerSnapshot, ManagerSnapshotScope, parse_manager_snapshots
    from aegis_verify.validation import EvaluationProfile

    checked = api.verify_run(**inputs)
    target = json.loads(inputs['study'])['target']
    records = []
    for name in ('sysmon1', 'powershell4104'):
        record = json.loads((ROOT / f'tests/fixtures/wazuh/windows-telemetry/{name}.synthetic.json').read_bytes())['_source']
        record['decoder'] = {'name': 'windows_eventchannel'}
        win = record['data']['win']
        win['system']['systemTime'] = '2026-01-01T00:00:10.223456789Z' if name == 'sysmon1' else '2026-01-01T00:00:11.123456789Z'
        if name == 'sysmon1':
            win['eventdata']['image'] = target['canonical_executable']
            win['eventdata']['commandLine'] = target['command_lines'][0]
        else:
            win['eventdata']['path'] = target['canonical_paths'][0]
            record['rule']['id'] = '119901' if detected else '91816'
        records.append(wire(record))
    raw = b'\n'.join(records)
    scope = ManagerSnapshotScope(target['agent_id'], target['hostname'], target['environment_id'],
                                 checked.context.start.isoformat(), checked.context.end.isoformat(),
                                 '2026-01-01T00:03:00Z')
    parsed = parse_manager_snapshots((ManagerSnapshot('synthetic-study', raw, sha(raw)),), scope=scope)
    result = evaluate_scenario(parse_scenario_yaml(inputs['scenario'].decode(), source_name='synthetic'),
                               tuple(d.telemetry.event for d in parsed.documents),
                               profile=EvaluationProfile.model_validate(json.loads(inputs['profile'])), context=checked.context)
    assert result.final_status == ('Detected' if detected else 'Inconclusive')
    assert result.assertions[2].reason_code == ('witness_found' if detected else 'collection_not_confirmed')
    assert result.assertions[0].outcome == result.assertions[1].outcome == 'satisfied'
    assert set(result.assertions[0].evidence_ids).issubset({d.telemetry.event.event_id for d in parsed.documents})


@pytest.mark.parametrize('field', ['canonical_executable', 'canonical_paths', 'command_lines'])
def test_native_representation_in_canonical_values_is_refused(api, inputs, field):
    """Guard for the defect measured on 2026-09-17.

    Wazuh delivers the JSON-escaped form in every decoded eventdata string, so a
    canonical value left in its native form can never match real telemetry. The
    study must be rejected rather than silently producing Missing telemetry on
    the first lab run.
    """
    study = json.loads(inputs['study'])
    target = study['target']
    if field == 'canonical_executable':
        target[field] = target['executable']
    else:
        target[field] = [json.loads('"' + value + '"') for value in target[field]]
    repin_study(inputs, study)
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


def test_canonical_executable_must_be_the_wire_form_of_the_native_one(api, inputs):
    study = json.loads(inputs['study'])
    study['target']['canonical_executable'] = wire_text('C:\\Other\\powershell.exe')
    repin_study(inputs, study)
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


def test_escaped_quotes_survive_the_wire_round_trip():
    """An escaped quote carries a single backslash; counting backslashes is wrong."""
    native = 'powershell -File "C:\\Synthetic\\x.ps1"'
    assert wire_text(native) == 'powershell -File \\"C:\\\\Synthetic\\\\x.ps1\\"'
    assert json.loads('"' + wire_text(native) + '"') == native


SEP = chr(92)


def test_canonical_paths_must_sit_in_the_reviewed_directory(api, inputs):
    """Anchoring only the executable would leave A02/A03 matching free-form."""
    study = json.loads(inputs['study'])
    target = study['target']
    elsewhere = 'D:' + SEP + 'Elsewhere'
    target['canonical_paths'] = [wire_text(elsewhere + SEP + name)
                                 for name in ('lab_update.ps1', 'maintenance_check.ps1')]
    repin_study(inputs, study)
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


def test_canonical_paths_must_not_add_subdirectories(api, inputs):
    study = json.loads(inputs['study'])
    target = study['target']
    target['canonical_paths'] = [wire_text(target['native_directory'] + SEP + 'nested' + SEP + name)
                                 for name in ('lab_update.ps1', 'maintenance_check.ps1')]
    repin_study(inputs, study)
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


def test_command_line_must_reference_its_own_payload_path(api, inputs):
    study = json.loads(inputs['study'])
    target = study['target']
    target['command_lines'] = [wire_text('totally unrelated ' + name)
                               for name in ('lab_update.ps1', 'maintenance_check.ps1')]
    repin_study(inputs, study)
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


def test_non_ascii_canonical_values_are_out_of_measured_scope(api, inputs):
    """The representation was measured on ASCII only; anything else must be measured."""
    study = json.loads(inputs['study'])
    target = study['target']
    accented = 'C:' + SEP + 'Synthétic' + SEP + 'powershell.exe'
    target['executable'] = accented
    target['canonical_executable'] = wire_text(accented)
    repin_study(inputs, study)
    with pytest.raises(api.StudyRunError):
        api.verify_run(**inputs)


@pytest.mark.parametrize('version, accepted', [
    ('0.2.0', True), ('0.3.0', True), ('0.4.0', False), ('0.3', False), ('0.1.0', False)])
def test_kit_version_is_the_v2_or_v3_contract_only(api, inputs, version, accepted):
    # 0.2.0 is the v2 lab set, 0.3.0 adds the runner exception (issue #91); pins decide the bytes.
    study, kit = json.loads(inputs['study']), json.loads(inputs['kit'])
    kit['kit_version'] = version
    inputs['kit'] = wire(kit)
    study['pins']['kit'] = sha(inputs['kit'])
    repin_study(inputs, study)
    if accepted:
        api.verify_run(**inputs)
    else:
        with pytest.raises(api.StudyRunError):
            api.verify_run(**inputs)
