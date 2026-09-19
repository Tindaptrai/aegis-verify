"""Synthetic end-to-end SCN-001 A/B/C evaluation.

Every byte here is test-only and generated in-process. Nothing in this file is
lab evidence, and the collection declarations built below are simulated operator
actions for software tests. They must never be copied into a real run: a real
`complete_for_scope` declaration can only be signed by a person who actually
confirmed collection for that scope and window.
"""

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_scn001_study_run import inputs, wire, sha, ROOT  # noqa: F401 - shared synthetic fixtures

from aegis_verify.compare import compare_reports
from aegis_verify.connectors.wazuh.manager_snapshot import ManagerSnapshotScope
from aegis_verify.demo.collection_review import approve_collection_request, prepare_collection_request
from aegis_verify.demo.evaluate import DemoEvaluationError, compare_demo_runs, evaluate_demo_run
from aegis_verify.demo.run import verify_run
from aegis_verify.demo.run_binding import review_run_binding
from aegis_verify.demo.snapshot_bundle import SnapshotFile, prepare_snapshot_bundle
from aegis_verify.intake.errors import IntakeError

SCENARIO = ROOT / 'scenarios/SCN-001-powershell-execution.yaml'
DEMO_RULE_ID = '119901'
PARENT_RULE_ID = '91816'
FILENAMES = ('lab_update.ps1', 'maintenance_check.ps1')
HOURS = {'A': 0, 'B': 1, 'C': 2}


def stamp(hour, minute, second, fraction='123456789'):
    return f'2026-01-01T{hour:02d}:{minute:02d}:{second:02d}.{fraction}Z'


def whole(hour, minute, second):
    return f'2026-01-01T{hour:02d}:{minute:02d}:{second:02d}Z'


def run_for(inputs, label, *, child_pid=4242):
    """Rebuild the pinned execution manifests for one reviewed run label."""
    hour = HOURS[label]
    study = json.loads(inputs['study'])
    target, pins = study['target'], study['pins']
    index = 0 if label == 'A' else 1
    revision = 'behavioral' if label == 'C' else 'baseline'
    path = target['native_directory'] + '\\' + FILENAMES[index]
    run_id = 'synthetic-' + label
    start = dict(
        kind='safe_demo_execution', execution_manifest_version='0.1.0', run_id=run_id, run_label=label,
        target_host=target['hostname'], scenario_id='SCN-001', scenario_version='0.1.0',
        payload_sha256=json.loads(inputs['kit'])['payload_sha256'], payload_path=path,
        rule_id=target['rule_id'], parent_sid=target['parent_sid'],
        applied_rule_revision_declared=revision, applied_rule_sha256_declared=pins[revision],
        rule_state_verified_remotely=False, runner_pid=4000, child_pid=None,
        executable=target['executable'],
        arguments='-NoLogo -NoProfile -NonInteractive -File "' + path + '"',
        window_start_utc=stamp(hour, 0, 0), window_planned_end_utc=stamp(hour, 2, 0),
        launch_utc=None, exit_observed_utc=None, window_observed_end_utc=None,
        exit_code=None, timed_out=False, status='started', failure_code=None)
    launched = start | dict(child_pid=child_pid, launch_utc=stamp(hour, 0, 10))
    final = launched | dict(exit_observed_utc=stamp(hour, 0, 11), exit_code=0, status='executed',
                            window_observed_end_utc=stamp(hour, 2, 0, '373456789'), elapsed_seconds=120.25)
    receipt = dict(kind='scn001_rule_receipt', version='0.1.0', run_id=run_id,
                   study_sha256=inputs['study_sha256'], execution_sha256=sha(wire(final)),
                   account=target['account'], elevated=target['elevated'],
                   before_rule_sha256=pins[revision], after_rule_sha256=pins[revision],
                   before_utc=whole(hour, 0, 0), after_utc=whole(hour, 2, 1),
                   confirmed_by='synthetic-operator', before_reference='synthetic-before',
                   after_reference='synthetic-after')
    return inputs | dict(execution_start=wire(start), execution_launched=wire(launched), execution=wire(final),
                         stdout=f'AEGIS_SAFE_DEMO_V1\r\nAEGIS_PID={child_pid}\r\n'.encode('ascii'),
                         receipt=wire(receipt))


def records_for(inputs, label, *, detected, alert_process_id=None, variant=None, companion=False):
    """Two synthetic decoded documents: process telemetry plus script telemetry."""
    hour = HOURS[label]
    index = (0 if label == 'A' else 1) if variant is None else variant
    target = json.loads(inputs['study'])['target']
    rows = []
    for name in ('sysmon1', 'powershell4104'):
        record = json.loads((ROOT / f'tests/fixtures/wazuh/windows-telemetry/{name}.synthetic.json').read_bytes())['_source']
        record['decoder'] = {'name': 'windows_eventchannel'}
        win = record['data']['win']
        win['system']['systemTime'] = stamp(hour, 0, 10, '223456789')
        if name == 'sysmon1':
            win['eventdata']['image'] = target['canonical_executable']
            win['eventdata']['commandLine'] = target['command_lines'][index]
        else:
            win['eventdata']['path'] = target['canonical_paths'][index]
            if alert_process_id is not None:
                win['system']['processID'] = str(alert_process_id)
            record['rule']['id'] = DEMO_RULE_ID if detected else PARENT_RULE_ID
        rows.append(wire(record))
    if companion:
        # PowerShell emits a script block for text that came from no file, so the
        # record carries no path, and nothing matched it, so it carries no rule.
        # Measured in the lab, every run produced one of these from its own child
        # alongside the payload's own block.
        extra = json.loads(rows[-1])
        extra.pop('rule', None)
        extra['data']['win']['system']['eventRecordID'] = '90001'
        extra['data']['win']['eventdata'].pop('path', None)
        extra['data']['win']['eventdata']['scriptBlockId'] = '00000000-0000-0000-0000-00000000000c'
        extra['data']['win']['eventdata']['scriptBlockText'] = '$global:?'
        rows.append(wire(extra))
    return rows


def bundle_for(space, inputs, label, *, detected, alert_process_id=None, suffix='', variant=None,
               ingested_minute=3, companion=False):
    hour = HOURS[label]
    checked = verify_run(**run_for(inputs, label))
    target = json.loads(inputs['study'])['target']
    source = space / f'source-{label}{suffix}.jsonl'
    source.write_bytes(b'\n'.join(records_for(inputs, label, detected=detected,
                                              alert_process_id=alert_process_id, variant=variant,
                                              companion=companion)))
    scope = ManagerSnapshotScope(target['agent_id'], target['hostname'], target['environment_id'],
                                 checked.context.start.isoformat(), checked.context.end.isoformat(),
                                 whole(hour, ingested_minute, 0))
    return prepare_snapshot_bundle(
        (SnapshotFile(source, 'synthetic-e2e', sha(source.read_bytes())),),
        scope=scope, profile=inputs['profile'],
        context=wire(checked.context.model_dump(mode='json')),
        destination=space / f'bundle-{label}{suffix}')


def attest(space, inputs, label, bundle, *, name=None):
    """Simulated operator approval. Never valid outside these software tests."""
    hour = HOURS[label]
    run_inputs = run_for(inputs, label)
    request = prepare_collection_request(bundle, run_inputs=run_inputs)
    approval = dict(kind='scn001_collection_approval', version='0.1.0', request_sha256=sha(request),
                    confirmed_by='synthetic-reviewer', reference='synthetic-collection-review',
                    collected_at=whole(hour, 3, 0), reviewed_at=whole(hour, 4, 0),
                    coverage_start=whole(hour, 0, 0), coverage_end=whole(hour, 2, 1),
                    no_sampling_or_truncation=True, no_parse_errors_or_gaps=True, clocks_adequate=True,
                    health_reference='synthetic-health', filter_reference='synthetic-filter',
                    rotation_reference='synthetic-rotation', backlog_reference='synthetic-backlog',
                    native_reference='synthetic-native-review', time_reference='synthetic-time')
    context = approve_collection_request(bundle, run_inputs=run_inputs, request=request, approval=wire(approval))
    path = space / (name or f'context-{label}-attested.json')
    path.write_bytes(context)
    return SimpleNamespace(path=path, request=request, approval=wire(approval))


def evaluate(inputs, label, bundle, attested=None, **overrides):
    extra = {}
    if attested is not None:
        extra = dict(context=attested.path, request=attested.request, approval=attested.approval)
    return evaluate_demo_run(bundle, run_inputs=run_for(inputs, label), scenario=SCENARIO,
                             **(extra | overrides))


def outcomes(report):
    return {item['assertion_id']: item['outcome'] for item in report['evaluation']['assertions']}


@pytest.fixture
def space():
    """Bundles must be written outside any repository, so pytest tmp_path will not do."""
    with tempfile.TemporaryDirectory(prefix='aegis-synthetic-e2e-') as directory:
        yield Path(directory)


@pytest.fixture
def run_a(space, inputs):
    return evaluate(inputs, 'A', bundle_for(space, inputs, 'A', detected=True))


@pytest.fixture
def run_c(space, inputs):
    return evaluate(inputs, 'C', bundle_for(space, inputs, 'C', detected=True))


@pytest.fixture
def run_b_attested(space, inputs):
    bundle = bundle_for(space, inputs, 'B', detected=False)
    return evaluate(inputs, 'B', bundle, attest(space, inputs, 'B', bundle))


def test_run_a_reports_detected_with_a_correlated_witness(run_a):
    assert run_a['evaluation']['final_status'] == 'Detected'
    assert outcomes(run_a) == {'SCN-001-A01': 'satisfied', 'SCN-001-A02': 'satisfied', 'SCN-001-A03': 'satisfied'}


@pytest.mark.parametrize('companion', [False, True])
def test_optional_native_review_preserves_evaluation_and_companion_limits(space, inputs, companion):
    from test_scn001_run_binding import native
    from aegis_verify.demo.snapshot_bundle import verify_snapshot_bundle
    bundle = bundle_for(space, inputs, 'A', detected=True, companion=companion)
    run_inputs = run_for(inputs, 'A')
    receipt = native(run_inputs, bundle)
    # Synthetic review names the bound payload, not the pathless companion.
    payload = next(d for d in verify_snapshot_bundle(bundle).documents
                   if d.parser == 'wazuh-powershell4104-v1' and d.telemetry.event.file_path is not None)
    receipt['records'][1]['evidence_id'] = payload.telemetry.event.event_id
    original = evaluate(inputs, 'A', bundle)
    reviewed = evaluate(inputs, 'A', bundle, native_review=wire(receipt))
    assert reviewed['evaluation'] == original['evaluation']
    assert reviewed['collection_review'] == original['collection_review']
    assert reviewed['input_fingerprints'] == original['input_fingerprints']
    assert reviewed['run_binding']['native_review_sha256'] == sha(wire(receipt))
    assert reviewed['run_binding']['status'] == ('unknown' if companion else 'caller_reviewed')
    assert reviewed['run_binding']['reasons'] == (['companion_record_unmatched'] if companion else [])
    compared = compare_demo_runs(before=reviewed, after=reviewed)
    assert compared['run_binding']['after']['native_review_sha256'] == sha(wire(receipt))


@pytest.mark.parametrize('change', ['hash', 'pid', 'malformed', 'wrong_type'])
def test_optional_native_review_rejects_bad_or_conflicting_inputs(space, inputs, change):
    from test_scn001_run_binding import native
    bundle = bundle_for(space, inputs, 'A', detected=True)
    receipt = native(run_for(inputs, 'A'), bundle)
    if change == 'hash':
        receipt['request_sha256'] = '0' * 64
    if change == 'pid':
        receipt['records'][0]['process_id'] = 9999
    raw = b'{' if change == 'malformed' else receipt if change == 'wrong_type' else wire(receipt)
    with pytest.raises(DemoEvaluationError, match='^invalid_demo_evaluation$'):
        evaluate(inputs, 'A', bundle, native_review=raw)


def test_native_review_does_not_attest_missing_alert_collection(space, inputs):
    from test_scn001_run_binding import native
    bundle = bundle_for(space, inputs, 'B', detected=False)
    run_inputs = run_for(inputs, 'B')
    receipt = native(run_inputs, bundle)
    receipt['payload_path'] = r'C:\Synthetic\AEGIS\maintenance_check.ps1'
    receipt['reviewed_at'] = '2026-01-01T01:04:00Z'
    for record in receipt['records']:
        record['event_time'] = '2026-01-01T01:00:10.223456789Z'
    original = evaluate(inputs, 'B', bundle)
    reviewed = evaluate(inputs, 'B', bundle, native_review=wire(receipt))
    assert reviewed['run_binding']['status'] == 'caller_reviewed'
    assert reviewed['evaluation'] == original['evaluation']
    assert reviewed['evaluation']['final_status'] == 'Inconclusive'
    assert reviewed['collection_review'] is None


def test_run_b_without_declaration_stays_inconclusive(space, inputs):
    report = evaluate(inputs, 'B', bundle_for(space, inputs, 'B', detected=False))
    assert report['evaluation']['final_status'] == 'Inconclusive'
    assert outcomes(report)['SCN-001-A03'] == 'inconclusive'


def test_run_b_with_declaration_is_a_false_negative(run_b_attested):
    assert run_b_attested['evaluation']['final_status'] == 'False negative'
    assert outcomes(run_b_attested) == {'SCN-001-A01': 'satisfied', 'SCN-001-A02': 'satisfied',
                                        'SCN-001-A03': 'false_negative'}


def test_pathless_script_block_does_not_block_an_attested_absence(space, inputs):
    # A record carrying no rule at all is definitely not the detection this
    # assertion looks for, so it must not turn an attested absence into an
    # unevaluable one. Without this, a real run can never reach a false negative,
    # because its own PowerShell always emits such a block.
    bundle = bundle_for(space, inputs, 'B', detected=False, companion=True, suffix='-companion')
    report = evaluate(inputs, 'B', bundle, attest(space, inputs, 'B', bundle, name='context-B-companion.json'))
    assert report['evaluation']['final_status'] == 'False negative'
    assert outcomes(report)['SCN-001-A03'] == 'false_negative'


def test_pathless_script_block_does_not_disturb_a_detection(space, inputs):
    # The same record alongside a real alert must leave the verdict untouched.
    report = evaluate(inputs, 'A', bundle_for(space, inputs, 'A', detected=True,
                                              companion=True, suffix='-companion'))
    assert report['evaluation']['final_status'] == 'Detected'
    assert outcomes(report)['SCN-001-A03'] == 'satisfied'


def test_a_rule_that_fired_but_is_not_the_demo_rule_stays_a_definite_non_match(space, inputs):
    # The guard must key on a rule being absent, never on the rule being wrong.
    # Run B's own alert carries the parent rule, and that is still a non-match.
    bundle = bundle_for(space, inputs, 'B', detected=False, suffix='-parent')
    report = evaluate(inputs, 'B', bundle, attest(space, inputs, 'B', bundle, name='context-B-parent.json'))
    assert report['evaluation']['final_status'] == 'False negative'


def test_run_c_detects_the_same_renamed_script(run_c):
    assert run_c['evaluation']['final_status'] == 'Detected'
    assert outcomes(run_c)['SCN-001-A03'] == 'satisfied'


def test_regression_passed_for_b_to_c(run_b_attested, run_c):
    comparison = compare_reports(before=run_b_attested, after=run_c)['comparison']
    assert comparison['status'] == 'Regression Passed'
    counts = comparison['assertion_state_counts']
    assert counts['improvement'] == 1 and counts['unchanged_pass'] == 2
    assert counts['regression'] == 0 and counts['unchanged_fail'] == 0


def test_evidence_ids_stay_traceable_across_both_runs(run_b_attested, run_c):
    for report in (run_b_attested, run_c):
        index = report['evaluation']['evidence_index']
        assert index and all(entry['event_id'] and entry['raw_event_ref'] and entry['raw_event_hash']
                             for entry in index)
    comparison = compare_reports(before=run_b_attested, after=run_c)['comparison']
    detection = next(item for item in comparison['assertions'] if item['assertion_id'] == 'SCN-001-A03')
    assert detection['after']['evidence_ids'] and detection['after']['evidence_refs']
    assert detection['evidence_changes']['added']


def test_missing_assurance_cannot_reach_regression_passed(space, inputs, run_c):
    before = evaluate(inputs, 'B', bundle_for(space, inputs, 'B', detected=False))
    comparison = compare_reports(before=before, after=run_c)['comparison']
    assert comparison['status'] == 'Inconclusive'
    assert comparison['assertion_state_counts']['improvement'] == 0


def test_uncorrelated_alert_is_refused_by_run_binding(space, inputs):
    """An alert on another process is a binding conflict, not a weaker verdict."""
    bundle = bundle_for(space, inputs, 'C', detected=True, alert_process_id=9999, suffix='-uncorrelated')
    binding = json.loads(review_run_binding(bundle, run_inputs=run_for(inputs, 'C')))
    assert binding['status'] == 'conflict'
    assert 'child_pid_mismatch' in binding['reasons']
    with pytest.raises(DemoEvaluationError):
        evaluate(inputs, 'C', bundle)


def test_run_a_telemetry_cannot_support_run_b(space, inputs):
    """The profile accepts either reviewed variant; run binding must still refuse."""
    bundle = bundle_for(space, inputs, 'B', detected=False, variant=0, suffix='-wrong-variant')
    binding = json.loads(review_run_binding(bundle, run_inputs=run_for(inputs, 'B')))
    assert binding['status'] == 'conflict'
    assert 'payload_variant_mismatch' in binding['reasons']
    with pytest.raises(DemoEvaluationError):
        evaluate(inputs, 'B', bundle)


def test_report_carries_the_run_binding_result(run_a):
    """A verdict must never be readable without its binding status beside it."""
    binding = run_a['run_binding']
    assert binding['kind'] == 'scn001_run_binding'
    assert binding['status'] == 'unknown'
    assert 'native_review_missing' in binding['reasons']
    assert binding['native_review_sha256'] is None
    assert binding['evidence']


@pytest.mark.parametrize('field,value', [('scenario_version', '0.2.0'), ('profile_version', '0.2.0')])
def test_incompatible_reports_are_refused(run_b_attested, run_c, field, value):
    after = json.loads(json.dumps(run_c))
    after['evaluation'][field] = value
    with pytest.raises(IntakeError):
        compare_reports(before=run_b_attested, after=after)


def test_attested_context_from_another_run_is_refused(space, inputs, run_c):
    bundle_b = bundle_for(space, inputs, 'B', detected=False)
    foreign = attest(space, inputs, 'B', bundle_b)
    bundle_c = bundle_for(space, inputs, 'C', detected=True, suffix='-foreign')
    with pytest.raises(DemoEvaluationError):
        evaluate(inputs, 'C', bundle_c, foreign)


def test_declaration_for_another_assertion_is_refused(space, inputs):
    """A context edited after approval no longer reproduces from request+approval."""
    bundle = bundle_for(space, inputs, 'B', detected=False)
    attested = attest(space, inputs, 'B', bundle)
    context = json.loads(attested.path.read_bytes())
    context['declarations'][0]['assertion_id'] = 'SCN-001-A01'
    moved = space / 'context-moved-declaration.json'
    moved.write_bytes(wire(context))
    tampered = SimpleNamespace(path=moved, request=attested.request, approval=attested.approval)
    with pytest.raises(DemoEvaluationError):
        evaluate(inputs, 'B', bundle, tampered)


def test_attested_context_without_its_approval_is_refused(space, inputs):
    """P1: equality with the verified context must not be enough on its own."""
    bundle = bundle_for(space, inputs, 'B', detected=False)
    attested = attest(space, inputs, 'B', bundle)
    with pytest.raises(DemoEvaluationError):
        evaluate_demo_run(bundle, run_inputs=run_for(inputs, 'B'), scenario=SCENARIO,
                          context=attested.path)


@pytest.mark.parametrize('drop', ['request', 'approval'])
def test_half_supplied_review_material_is_refused(space, inputs, drop):
    bundle = bundle_for(space, inputs, 'B', detected=False)
    attested = attest(space, inputs, 'B', bundle)
    kwargs = dict(context=attested.path, request=attested.request, approval=attested.approval)
    kwargs[drop] = None
    with pytest.raises(DemoEvaluationError):
        evaluate_demo_run(bundle, run_inputs=run_for(inputs, 'B'), scenario=SCENARIO, **kwargs)


def test_review_material_without_a_context_is_refused(space, inputs):
    bundle = bundle_for(space, inputs, 'B', detected=False)
    attested = attest(space, inputs, 'B', bundle)
    with pytest.raises(DemoEvaluationError):
        evaluate_demo_run(bundle, run_inputs=run_for(inputs, 'B'), scenario=SCENARIO,
                          request=attested.request, approval=attested.approval)


def test_approval_from_another_snapshot_is_refused(space, inputs):
    """Same run and window, a second valid snapshot: the approval must not carry."""
    first = bundle_for(space, inputs, 'B', detected=False)
    attested = attest(space, inputs, 'B', first)
    # A genuinely different capture of the same window, not a byte-identical copy.
    second = bundle_for(space, inputs, 'B', detected=False, suffix='-resnapshot', ingested_minute=5)
    with pytest.raises(DemoEvaluationError):
        evaluate_demo_run(second, run_inputs=run_for(inputs, 'B'), scenario=SCENARIO,
                          context=attested.path, request=attested.request, approval=attested.approval)


def test_approval_from_another_run_is_refused(space, inputs):
    bundle_b = bundle_for(space, inputs, 'B', detected=False)
    attested = attest(space, inputs, 'B', bundle_b)
    bundle_c = bundle_for(space, inputs, 'C', detected=True, suffix='-foreign-approval')
    with pytest.raises(DemoEvaluationError):
        evaluate_demo_run(bundle_c, run_inputs=run_for(inputs, 'C'), scenario=SCENARIO,
                          context=attested.path, request=attested.request, approval=attested.approval)


def test_scenario_must_match_the_pinned_study(space, inputs):
    bundle = bundle_for(space, inputs, 'A', detected=True)
    altered = space / 'altered-scenario.yaml'
    altered.write_bytes(inputs['scenario'] + b'\n# synthetic edit\n')
    with pytest.raises(DemoEvaluationError):
        evaluate_demo_run(bundle, run_inputs=run_for(inputs, 'A'), scenario=altered)


def test_bundle_profile_must_match_the_reviewed_run(space, inputs):
    bundle = bundle_for(space, inputs, 'A', detected=True)
    run_inputs = run_for(inputs, 'A') | {'profile': inputs['profile'] + b' '}
    with pytest.raises(DemoEvaluationError):
        evaluate_demo_run(bundle, run_inputs=run_inputs, scenario=SCENARIO)


def test_orchestration_never_creates_an_attestation(space, inputs):
    """Without an approved context the tool must not invent collection assurance."""
    report = evaluate(inputs, 'B', bundle_for(space, inputs, 'B', detected=False))
    assert report['evaluation'].get('collection_assurance') in (None, 'unknown')


def test_report_fingerprints_match_the_reviewed_bytes(space, inputs):
    """The report must describe the reviewed profile, scenario and attested context."""
    bundle = bundle_for(space, inputs, 'B', detected=False)
    attested = attest(space, inputs, 'B', bundle)
    report = evaluate(inputs, 'B', bundle, attested)
    fingerprints = report['input_fingerprints']
    assert fingerprints['profile'] == sha(inputs['profile'])
    assert fingerprints['scenario'] == sha(inputs['scenario'])
    assert fingerprints['context'] == sha(attested.path.read_bytes())


def test_report_describing_other_input_bytes_is_refused(space, inputs, monkeypatch):
    """Fault injection: a report whose inputs differ from the checked bytes is rejected."""
    import aegis_verify.demo.evaluate as module
    bundle = bundle_for(space, inputs, 'A', detected=True)
    original = module.evaluate_bundle

    def tampered(scenario, root, *, context=None):
        report = original(scenario, root, context=context)
        report['input_fingerprints']['context'] = '0' * 64
        return report

    monkeypatch.setattr(module, 'evaluate_bundle', tampered)
    with pytest.raises(DemoEvaluationError):
        evaluate(inputs, 'A', bundle)


def test_demo_comparison_keeps_both_run_bindings(run_b_attested, run_c):
    """P2: the limits of each run must travel with the Regression Passed verdict."""
    comparison = compare_demo_runs(before=run_b_attested, after=run_c)
    assert comparison['comparison']['status'] == 'Regression Passed'
    binding = comparison['run_binding']
    assert set(binding) == {'before', 'after'}
    for side, expected_run in (('before', 'synthetic-B'), ('after', 'synthetic-C')):
        assert binding[side]['run_id'] == expected_run
        assert binding[side]['status'] == 'unknown'
        assert 'native_review_missing' in binding[side]['reasons']
        assert binding[side]['both_sides_caller_declared'] is True
        assert binding[side]['native_review_sha256'] is None


def test_demo_comparison_does_not_change_the_engine_verdict(run_b_attested, run_c):
    plain = compare_reports(before=run_b_attested, after=run_c)
    carried = compare_demo_runs(before=run_b_attested, after=run_c)
    assert carried['comparison'] == plain['comparison']


def test_demo_comparison_refuses_a_report_without_a_binding(run_b_attested, run_c):
    stripped = json.loads(json.dumps(run_c))
    stripped.pop('run_binding')
    with pytest.raises(DemoEvaluationError):
        compare_demo_runs(before=run_b_attested, after=stripped)


def test_comparison_refuses_bindings_swapped_between_reports(run_b_attested, run_c):
    """The attachment must belong to the report it decorates."""
    swapped_before = json.loads(json.dumps(run_b_attested))
    swapped_after = json.loads(json.dumps(run_c))
    swapped_before['run_binding'], swapped_after['run_binding'] = (
        swapped_after['run_binding'], swapped_before['run_binding'])
    with pytest.raises(DemoEvaluationError):
        compare_demo_runs(before=swapped_before, after=swapped_after)


def test_comparison_refuses_a_binding_claiming_independent_review(run_b_attested, run_c):
    """A forged caller_reviewed binding must not be copied into the output."""
    forged = json.loads(json.dumps(run_c))
    forged['run_binding'] = forged['run_binding'] | {
        'status': 'caller_reviewed', 'reasons': [], 'both_sides_caller_declared': False}
    with pytest.raises(DemoEvaluationError):
        compare_demo_runs(before=run_b_attested, after=forged)


def test_report_records_which_review_produced_the_assurance(run_b_attested, space, inputs):
    review = run_b_attested['collection_review']
    assert review['assurance'] == 'caller-attested'
    assert len(review['request_sha256']) == 64 and len(review['approval_sha256']) == 64
    assert review['request_sha256'] != review['approval_sha256']


def test_report_without_attestation_records_no_review(space, inputs):
    report = evaluate(inputs, 'B', bundle_for(space, inputs, 'B', detected=False))
    assert report['collection_review'] is None
    assert report['evaluation']['final_status'] == 'Inconclusive'


def test_report_pins_the_rule_chain_of_its_run(run_a):
    demo = run_a['demo_run']
    assert demo['run_label'] == 'A'
    assert demo['applied_rule_revision_declared'] == 'baseline'
    assert demo['rule_id'] == 119901 and demo['parent_sid'] == 91816


def test_comparison_refuses_a_changed_parent_rule(run_b_attested, run_c):
    """Re-parenting between B and C must not be credited to the content fix."""
    reparented = json.loads(json.dumps(run_c))
    reparented['demo_run']['parent_sid'] = 91802
    with pytest.raises(DemoEvaluationError):
        compare_demo_runs(before=run_b_attested, after=reparented)


def test_comparison_refuses_a_changed_rule_id(run_b_attested, run_c):
    renumbered = json.loads(json.dumps(run_c))
    renumbered['demo_run']['rule_id'] = 118001
    with pytest.raises(DemoEvaluationError):
        compare_demo_runs(before=run_b_attested, after=renumbered)


def test_comparison_allows_the_revision_to_differ(run_b_attested, run_c):
    carried = compare_demo_runs(before=run_b_attested, after=run_c)
    assert carried['demo_run']['before']['applied_rule_revision_declared'] == 'baseline'
    assert carried['demo_run']['after']['applied_rule_revision_declared'] == 'behavioral'
    assert carried['comparison']['status'] == 'Regression Passed'
