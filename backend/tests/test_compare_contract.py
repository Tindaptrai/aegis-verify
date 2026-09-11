"""Issue #9 contract regressions; all evidence and attestations are synthetic."""

from copy import deepcopy
import json

import pytest

from aegis_verify.cli.reporting import render_report
from aegis_verify.cli.service import evaluate_bundle
from aegis_verify.compare import compare_runs
from aegis_verify.compare.service import _assertion_state
from aegis_verify.intake import IntakeError
from test_cli_compare import write_synthetic_case


@pytest.fixture
def reports(tmp_path):
    result = {}
    for name, rule, attested, records in (
        ("pass", "67027", False, 2), ("gap", "99999", True, 2),
        ("unknown", "99999", False, 2), ("missing", "99999", False, 0),
    ):
        scenario, fixture = write_synthetic_case(
            tmp_path / name, evidence_rule_id=rule, attested=attested,
            run_id=name, records=records,
        )
        result[name] = evaluate_bundle(scenario, fixture)
    return result


def compare(tmp_path, before, after):
    left, right = tmp_path / "before.json", tmp_path / "after.json"
    left.write_text(json.dumps(before), encoding="utf-8")
    right.write_text(json.dumps(after), encoding="utf-8")
    return compare_runs(before=left, after=right)


@pytest.mark.parametrize("before,after,want", [
    ("satisfied", "satisfied", "unchanged_pass"),
    ("satisfied", "false_negative", "regression"),
    ("false_negative", "satisfied", "improvement"),
    ("false_negative", "false_negative", "unchanged_fail"),
    ("inconclusive", "inconclusive", "unchanged_unknown"),
    ("missing_telemetry", "missing_telemetry", "unchanged_unknown"),
    ("inconclusive", "missing_telemetry", "unknown_changed"),
    ("missing_telemetry", "inconclusive", "unknown_changed"),
    ("inconclusive", "satisfied", "became_evaluable"),
    ("missing_telemetry", "satisfied", "became_evaluable"),
    ("inconclusive", "false_negative", "became_evaluable"),
    ("missing_telemetry", "false_negative", "became_evaluable"),
    ("satisfied", "inconclusive", "became_unevaluable"),
    ("satisfied", "missing_telemetry", "became_unevaluable"),
    ("false_negative", "inconclusive", "became_unevaluable"),
    ("false_negative", "missing_telemetry", "became_unevaluable"),
])
def test_all_outcome_transitions(before, after, want):
    assert _assertion_state(before, after) == want


@pytest.mark.parametrize("before,after,want", [
    ("gap", "pass", "Regression Passed"), ("pass", "gap", "Regression"),
    ("gap", "gap", "Unchanged mixed"), ("pass", "pass", "Unchanged pass"),
    ("unknown", "pass", "Inconclusive"), ("missing", "pass", "Inconclusive"),
    ("pass", "unknown", "Inconclusive"), ("missing", "missing", "Inconclusive"),
])
def test_real_engine_runs_preserve_unknown_status(tmp_path, reports, before, after, want):
    result = compare(tmp_path, reports[before], reports[after])
    assert result["comparison"]["status"] == want


def test_partial_fix_is_not_regression_passed():
    from collections import Counter
    from aegis_verify.compare.service import _state_status
    assert _state_status(Counter(improvement=1, unchanged_fail=1)) == "Improved with remaining gaps"


def test_text_keeps_complete_ids_and_json_preserves_witnesses(tmp_path, reports):
    result = compare(tmp_path, reports["gap"], reports["pass"])
    text = render_report(result, "text")
    assertion = result["comparison"]["assertions"][1]
    ids = assertion["after"]["evidence_ids"]
    assert "  After Evidence IDs: " + ", ".join(ids) in text
    assert assertion["after"]["witness_pairs"] == reports["pass"]["evaluation"]["assertions"][1]["witness_pairs"]
    assert assertion["evidence_changes"]["added"] == sorted(set(ids) - set(assertion["before"]["evidence_ids"]))


@pytest.mark.parametrize("mutation", ["duplicate", "witness", "counts", "final", "assurance", "role", "reason", "version", "no_metadata"])
def test_invalid_report_rejected_without_partial_verdict(tmp_path, reports, mutation):
    bad = deepcopy(reports["pass"])
    evaluation = bad["evaluation"]
    if mutation == "duplicate":
        evaluation["assertions"].append(deepcopy(evaluation["assertions"][0]))
    elif mutation == "witness":
        evaluation["assertions"][1]["witness_pairs"][0]["target_event_id"] = "nonexistent"
    elif mutation == "counts":
        evaluation["counts"]["satisfied"] = 999
    elif mutation == "final":
        evaluation["final_status"] = "False negative"
    elif mutation == "assurance":
        evaluation["assertions"][1]["collection_assurance"] = "caller-attested"
    elif mutation == "role":
        evaluation["assertions"][1]["role"] = "telemetry"
    elif mutation == "reason":
        evaluation["assertions"][1]["reason_code"] = "expected_detection_absent"
    elif mutation == "version":
        bad["cli_report_version"] = "999.0"
    else:
        bad.pop("comparison_inputs", None)
    with pytest.raises(IntakeError):
        compare(tmp_path, reports["pass"], bad)


def test_metadata_is_bound_to_context_fingerprint(tmp_path, reports):
    bad = deepcopy(reports["pass"])
    # Missing metadata in the original implementation is itself the regression.
    bad.setdefault("comparison_inputs", {}).setdefault("context", {})["environment_id"] = "other-lab"
    with pytest.raises(IntakeError):
        compare(tmp_path, reports["pass"], bad)


@pytest.mark.parametrize("field,value", [("environment_id", "other-lab"), ("bindings", [{"name": "target", "value": "other-host"}]), ("end", "2026-01-01T00:02:00Z")])
def test_real_engine_different_scope_rejected(tmp_path, reports, field, value):
    from aegis_verify.validation import EvaluationContext, EvaluationProfile, evaluate_scenario
    from aegis_verify.models.scenario import ScenarioManifest
    bad = deepcopy(reports["pass"])
    inputs = bad.get("comparison_inputs")
    assert inputs is not None, "validate must export comparison inputs"
    inputs["context"][field] = value
    context = EvaluationContext.model_validate(inputs["context"])
    bad["evaluation"] = evaluate_scenario(
        ScenarioManifest.model_validate(inputs["scenario"]), [],
        profile=EvaluationProfile.model_validate(inputs["profile"]), context=context,
    ).model_dump(mode="json")
    with pytest.raises(IntakeError, match="comparison_incompatible"):
        compare(tmp_path, reports["pass"], bad)


def test_shifted_time_and_run_id_are_compatible(tmp_path, reports):
    from aegis_verify.validation import EvaluationContext, EvaluationProfile, evaluate_scenario
    from aegis_verify.models.scenario import ScenarioManifest
    other = deepcopy(reports["missing"])
    inputs = other.get("comparison_inputs")
    assert inputs is not None, "validate must export comparison inputs"
    inputs["context"].update(run_id="later", start="2026-01-02T00:00:00Z", end="2026-01-02T00:01:00Z")
    other["evaluation"] = evaluate_scenario(
        ScenarioManifest.model_validate(inputs["scenario"]), [],
        profile=EvaluationProfile.model_validate(inputs["profile"]),
        context=EvaluationContext.model_validate(inputs["context"]),
    ).model_dump(mode="json")
    assert compare(tmp_path, reports["missing"], other)["comparison"]["status"] == "Inconclusive"


def test_in_memory_api_does_not_mutate_inputs(reports):
    import aegis_verify.compare as api
    original = deepcopy(reports)
    assert hasattr(api, "compare_reports"), "comparison library needs an in-memory entry point"
    result = api.compare_reports(before=reports["gap"], after=reports["pass"])
    assert result["comparison"]["status"] == "Regression Passed"
    assert reports == original


@pytest.mark.parametrize("mutation", ["self_pair", "clear_pairs", "bad_anchor", "duplicate_index", "unknown_id", "clear_ids"])
def test_evidence_invariants(tmp_path, reports, mutation):
    bad = deepcopy(reports["pass"])
    item = bad["evaluation"]["assertions"][1]
    if mutation == "self_pair":
        item["witness_pairs"][0]["anchor_event_id"] = item["witness_pairs"][0]["target_event_id"]
    elif mutation == "clear_pairs":
        item["witness_pairs"] = []
    elif mutation == "bad_anchor":
        item["witness_pairs"][0]["anchor_event_id"] = "missing-anchor"
    elif mutation == "duplicate_index":
        bad["evaluation"]["evidence_index"].append(deepcopy(bad["evaluation"]["evidence_index"][0]))
    elif mutation == "unknown_id":
        item["unevaluable_evidence_ids"] = ["not-in-index"]
    else:
        item["evidence_ids"] = []
    with pytest.raises(IntakeError):
        compare(tmp_path, reports["pass"], bad)


@pytest.mark.parametrize("field,value", [("profile_id", "different"), ("profile_version", "0.2.0"), ("scenario_version", "0.2.0"), ("scenario_fingerprint", "a" * 64), ("profile_fingerprint", "b" * 64), ("engine_semantics_version", "0.2.0")])
def test_inconsistent_identity_rejected(tmp_path, reports, field, value):
    bad = deepcopy(reports["pass"])
    bad["evaluation"][field] = value
    with pytest.raises(IntakeError):
        compare(tmp_path, reports["pass"], bad)


@pytest.mark.parametrize("data,code", [(b'', 'invalid_json'), (b'{', 'invalid_json'), (b'{"kind":"evaluation","kind":"evaluation"}', 'invalid_json'), (b'{"value":NaN}', 'invalid_number'), (b'[]', 'invalid_json'), (b'{}' + b' ' * 1048576, 'input_too_large')], ids=['empty', 'truncated', 'duplicate-key', 'nan', 'array', 'oversized'])
def test_invalid_json_cli_has_error_only(tmp_path, data, code):
    from test_cli_compare import run_compare_cli
    path = tmp_path / "bad.json"
    path.write_bytes(data)
    result = run_compare_cli('--before', str(path), '--after', str(path), '--format=json')
    assert result.returncode == 2
    assert result.stdout == ''
    error = json.loads(result.stderr)['error']
    assert error['code'] == code
    assert error['stage'] == 'comparison'


def test_powershell_utf8_bom_accepted(tmp_path, reports):
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(reports['pass']), encoding='utf-8-sig')
    assert compare_runs(before=path, after=path)['comparison']['status'] == 'Unchanged pass'


def engine_report(manifest, profile, context, events):
    from aegis_verify.validation import evaluate_scenario
    return {
        'cli_report_version': '0.1.0', 'kind': 'evaluation',
        'scenario': {'id': manifest.id, 'version': manifest.version, 'name': manifest.name},
        'comparison_inputs': {'version': '0.1.0', 'scenario': manifest.model_dump(mode='json'),
                              'profile': profile.model_dump(mode='json'), 'context': context.model_dump(mode='json')},
        'evaluation': evaluate_scenario(manifest, events, profile=profile, context=context).model_dump(mode='json'),
    }


@pytest.mark.parametrize('mode', ['unknown_fields', 'missing', 'unsupported', 'prevented', 'prevention_absent'])
def test_other_engine_outcomes_remain_comparable(tmp_path, mode):
    from test_validation_acceptance import _inputs
    from aegis_verify.validation import EvaluationProfile, scenario_fingerprint
    manifest, events, profile, context = _inputs()
    if mode == 'unknown_fields':
        events = [event.model_copy(update={'hostname': None}) for event in events]
    elif mode == 'missing':
        events = []
    elif mode == 'unsupported':
        data = profile.model_dump(mode='json')
        data['rules'][1] = {'assertion_id': 'SCN-999-A02', 'role': 'detection', 'capability': 'unsupported', 'reason_code': 'synthetic-only'}
        profile = EvaluationProfile.model_validate(data)
    else:
        manifest = type(manifest).model_validate(manifest.model_dump(mode='json') | {'expected_outcome': 'prevented'})
        data = profile.model_dump(mode='json')
        data['scenario_fingerprint'] = scenario_fingerprint(manifest)
        data['rules'][1]['role'] = 'prevention'
        data['rules'][1]['match'] = [{'field': 'event_action', 'op': 'eq', 'value': 'blocked'}]
        profile = EvaluationProfile.model_validate(data)
        if mode == 'prevented':
            events[1] = events[1].model_copy(update={'event_action': 'blocked'})
    report = engine_report(manifest, profile, context, events)
    expected = 'Unchanged pass' if mode == 'prevented' else 'Inconclusive'
    assert compare(tmp_path, report, report)['comparison']['status'] == expected


@pytest.mark.parametrize('change', ['profile', 'scenario'])
def test_genuine_changed_contract_rejected(tmp_path, change):
    from test_validation_acceptance import _inputs
    from aegis_verify.validation import EvaluationProfile, scenario_fingerprint
    manifest, events, profile, context = _inputs()
    before = engine_report(manifest, profile, context, events)
    data = profile.model_dump(mode='json')
    if change == 'profile':
        data['rules'][1]['match'][0]['value'] = 'synthetic-new-rule'
    else:
        manifest = manifest.model_copy(update={'description': 'Changed synthetic ground truth description'})
        data['scenario_fingerprint'] = scenario_fingerprint(manifest)
    profile = EvaluationProfile.model_validate(data)
    after = engine_report(manifest, profile, context, events)
    with pytest.raises(IntakeError, match='comparison_incompatible'):
        compare(tmp_path, before, after)


def test_real_partial_detection_fix_keeps_remaining_gap(tmp_path):
    from test_validation_acceptance import _inputs
    from aegis_verify.validation import (
        EvaluationProfile, EvaluationContext, scenario_fingerprint,
        profile_fingerprint, scope_fingerprint, event_set_fingerprint,
    )
    manifest, events, profile, context = _inputs()
    data = manifest.model_dump(mode='json')
    data['assertions'].append({'id': 'SCN-999-A03', 'description': 'Second synthetic detection', 'source': 'wazuh'})
    manifest = type(manifest).model_validate(data)
    data = profile.model_dump(mode='json')
    data['scenario_fingerprint'] = scenario_fingerprint(manifest)
    second = deepcopy(data['rules'][1])
    second['assertion_id'] = 'SCN-999-A03'
    second['match'][0]['value'] = 'synthetic-second-rule'
    data['rules'].append(second)
    profile = EvaluationProfile.model_validate(data)
    reports = []
    for selected in (events[:1], events):
        declarations = [{
            'assertion_id': identifier, 'status': 'complete_for_scope',
            'confirmed_by': 'synthetic-reviewer', 'reference': 'synthetic-only/attestation',
            'coverage_start': context.start.isoformat(), 'coverage_end': context.end.isoformat(),
            'no_sampling_or_truncation': True, 'no_parse_errors_or_gaps': True, 'clocks_adequate': True,
            'profile_fingerprint': profile_fingerprint(profile),
            'scope_fingerprint': scope_fingerprint(context), 'event_set_fingerprint': event_set_fingerprint(selected),
        } for identifier in ('SCN-999-A02', 'SCN-999-A03')]
        attested = EvaluationContext.model_validate(context.model_dump(mode='json') | {'declarations': declarations})
        reports.append(engine_report(manifest, profile, attested, selected))
    result = compare(tmp_path, *reports)
    assert result['comparison']['status'] == 'Improved with remaining gaps'
    assert result['after']['final_status'] == 'False negative'
    assert result['comparison']['assertion_state_counts']['unchanged_fail'] == 1
