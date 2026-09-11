"""Offline outcomes from synthetic evidence; never a lab ground-truth claim."""
import itertools

import pytest

import aegis_verify.validation as api
from validation_cases import event
from test_validation_boundaries import complete, evaluate, inputs


def target(**changes):
    return event(event_id="detection", event_action="other", rule_id="synthetic-reviewed-rule",
                 timestamp="2026-01-01T00:00:02.000000001Z", **changes)


def change_rule(profile, index, **changes):
    rules = list(profile.rules)
    rules[index] = rules[index].model_copy(update=changes)
    return profile.model_copy(update={"rules": tuple(rules)})


@pytest.mark.parametrize("case,status,reason", [
    ("empty", "Missing telemetry", "missing_activity_anchor"),
    ("unknown_anchor", "Inconclusive", "uncertain_activity_anchor"),
    ("detection", "Detected", "witness_found"),
    ("prevention", "Prevented", "witness_found"),
    ("unknown_collection", "Inconclusive", "collection_not_confirmed"),
    ("complete_collection", "False negative", "expected_detection_absent"),
    ("no_block", "Inconclusive", "prevention_not_demonstrated"),
    ("unsupported", "Inconclusive", "unsupported_requirement"),
])
def test_five_statuses_and_missing_reasons(case, status, reason):
    prevention = case in {"prevention", "no_block"}
    manifest, events, profile, context = inputs(role="prevention" if prevention else "detection", expected="prevented" if prevention else "detected")
    if case == "empty": events = [target()]
    if case == "unknown_anchor": events = [events[0].model_copy(update={"event_action": None}), target()]
    if case == "detection": events.append(target())
    if case == "prevention": events.append(target().model_copy(update={"event_action": "blocked"}))
    if case == "complete_collection": context = complete(profile, context, events)
    if case == "unsupported":
        profile = profile.model_copy(update={"rules": (profile.rules[0], api.AssertionRule(assertion_id="SCN-999-A02", role="detection", capability="unsupported", reason_code="requires_session_identity"))})
    result = evaluate(manifest, events, profile, context)
    assert result.final_status == status
    assert result.assertions[1].reason_code == reason
    if case in {"detection", "prevention"}:
        assert result.assertions[1].evidence_ids == ("activity", "detection")
        assert result.assertions[1].witness_pairs == (api.WitnessPair(target_event_id="detection", anchor_event_id="activity"),)
    if case == "complete_collection":
        assert result.assertions[1].evidence_ids == ("activity",)
        assert result.assertions[1].collection_assurance == "caller-attested"
        assert result.assertions[1].collection_reference == "synthetic-collection-report"
    if case == "empty":
        assert result.assertions[0].evidence_ids == ()
        assert result.assertions[0].reason_code == "activity_not_found_in_input"
        assert result.evidence_index == ()


@pytest.mark.parametrize("field,value", [("environment_id", "different"), ("hostname", "different"),
    ("source_type", "cowrie"), ("rule_id", "unreviewed"), ("timestamp", "2026-01-01T00:02:00Z")])
def test_unrelated_alerts_do_not_satisfy_detection(field, value):
    manifest, events, profile, context = inputs()
    events.append(target().model_copy(update={field: value}))
    context = complete(profile, context, events)
    result = evaluate(manifest, events, profile, context)
    assert result.final_status == "False negative"
    assert tuple(entry.event_id for entry in result.evidence_index) == ("activity",)


@pytest.mark.parametrize("action", ["allowed", "redirected", "other"])
def test_nonblocking_action_cannot_prove_prevention(action):
    manifest, events, profile, context = inputs(role="prevention", expected="prevented")
    events.append(target().model_copy(update={"event_action": action}))
    assert evaluate(manifest, events, profile, context).assertions[1].reason_code == "prevention_not_demonstrated"


@pytest.mark.parametrize("source", ["sysmon", "powershell"])
def test_logical_source_uses_explicit_provider(source):
    manifest, events, profile, context = inputs(source=source)
    events = [e.model_copy(update={"event_provider": "synthetic-provider"}) for e in events + [target()]]
    assert evaluate(manifest, events, profile, context).final_status == "Detected"
    events[1] = events[1].model_copy(update={"event_provider": "different-provider"})
    assert evaluate(manifest, events, profile, context).assertions[1].reason_code == "collection_not_confirmed"


@pytest.mark.parametrize("known_false", [False, True])
def test_false_dominates_unknown_in_scope_and_match(known_false):
    manifest, events, profile, context = inputs()
    extra = api.Predicate(field="process_name", op="eq", value="synthetic-process")
    profile = change_rule(profile, 1, match=profile.rules[1].match + (extra,))
    candidate = target().model_copy(update={"hostname": "different" if known_false else None})
    events.append(candidate)
    context = complete(profile, context, events)
    assertion = evaluate(manifest, events, profile, context).assertions[1]
    assert assertion.reason_code == ("expected_detection_absent" if known_false else "insufficient_fields")
    assert assertion.unevaluable_evidence_ids == (() if known_false else ("detection",))


def test_same_pair_must_match_every_join_field():
    manifest, events, profile, context = inputs()
    events = [events[0].model_copy(update={"event_id": "a", "process_id": 1, "src_port": 10}),
              events[0].model_copy(update={"event_id": "b", "process_id": 2, "src_port": 20}),
              target(process_id=1, src_port=20)]
    correlation = profile.rules[1].correlation.model_copy(update={"join_pairs": (
        api.JoinPair(target_field="process_id", anchor_field="process_id"), api.JoinPair(target_field="src_port", anchor_field="src_port"))})
    profile = change_rule(profile, 1, correlation=correlation)
    context = complete(profile, context, events)
    assertion = evaluate(manifest, events, profile, context).assertions[1]
    assert assertion.outcome == "false_negative"
    assert assertion.evidence_ids == ("a", "b")
    assert assertion.witness_pairs == ()
    events[1] = events[1].model_copy(update={"process_id": 1})
    context = complete(profile, context, events)
    assertion = evaluate(manifest, events, profile, context).assertions[1]
    assert assertion.witness_pairs == (api.WitnessPair(target_event_id="detection", anchor_event_id="b"),)
    assert assertion.evidence_ids == ("b", "detection")


def test_no_self_witness_but_distinct_ids_with_same_hash_are_allowed():
    manifest, events, profile, context = inputs()
    profile = change_rule(profile, 1, match=(profile.rules[1].match[0],))
    events = [events[0].model_copy(update={"rule_id": "synthetic-reviewed-rule"})]
    context = complete(profile, context, events)
    assert evaluate(manifest, events, profile, context).final_status == "False negative"
    events.append(events[0].model_copy(update={"event_id": "second"}))
    context = complete(profile, context, events)
    assertion = evaluate(manifest, events, profile, context).assertions[1]
    assert assertion.outcome == "satisfied"
    assert [(p.target_event_id, p.anchor_event_id) for p in assertion.witness_pairs] == [("activity", "second"), ("second", "activity")]


@pytest.mark.parametrize("port,delta,want", [(None, 0, "insufficient_fields"), (20, 0, "expected_detection_absent"),
    (None, 2_000_000_000, "expected_detection_absent")])
def test_unknown_join_only_potential_if_no_other_field_or_time_is_false(port, delta, want):
    manifest, events, profile, context = inputs()
    events[0] = events[0].model_copy(update={"src_port": 10})
    events.append(target(src_port=port))
    profile = change_rule(profile, 1, correlation=profile.rules[1].correlation.model_copy(update={
        "join_pairs": (api.JoinPair(target_field="process_id", anchor_field="process_id"), api.JoinPair(target_field="src_port", anchor_field="src_port")),
        "min_delta_ns": delta, "max_delta_ns": delta + 1_000_000_000}))
    context = complete(profile, context, events)
    assert evaluate(manifest, events, profile, context).assertions[1].reason_code == want


def test_positive_existential_witness_wins_but_keeps_unknown_candidates_separate():
    manifest, events, profile, context = inputs()
    events += [target(), target().model_copy(update={"event_id": "unknown", "hostname": None})]
    result = evaluate(manifest, events, profile, context)
    assert result.final_status == "Detected"
    assert result.assertions[1].evidence_ids == ("activity", "detection")
    assert result.assertions[1].unevaluable_evidence_ids == ("unknown",)


@pytest.mark.parametrize("timestamp,want", [("2026-01-01T00:00:00.999999999Z", "missing_telemetry"),
    ("2026-01-01T00:00:01.000000000Z", "satisfied"), ("2026-01-01T00:00:01.000000002Z", "satisfied"),
    ("2026-01-01T00:00:01.000000003Z", "missing_telemetry")])
def test_closed_scope_window_preserves_one_nanosecond_boundaries(timestamp, want):
    manifest, events, profile, context = inputs()
    context = api.EvaluationContext(**(context.model_dump() | {"start": "2026-01-01T00:00:01.000000000Z", "end": "2026-01-01T00:00:01.000000002Z"}))
    events[0] = events[0].model_copy(update={"timestamp": timestamp})
    assert evaluate(manifest, events, profile, context).assertions[0].outcome == want


@pytest.mark.parametrize("timestamp,want", [("2026-01-01T00:00:01.000000000Z", "satisfied"),
    ("2026-01-01T00:00:00.999999999Z", "false_negative"), ("2026-01-01T00:00:01.000000002Z", "satisfied"),
    ("2026-01-01T00:00:01.000000003Z", "false_negative"), ("2026-01-01T07:00:01.000000001+07:00", "satisfied")])
def test_signed_closed_join_delta_uses_nanoseconds(timestamp, want):
    manifest, events, profile, context = inputs()
    profile = change_rule(profile, 1, correlation=profile.rules[1].correlation.model_copy(update={"min_delta_ns": -1, "max_delta_ns": 1}))
    events.append(target().model_copy(update={"timestamp": timestamp}))
    context = complete(profile, context, events)
    assert evaluate(manifest, events, profile, context).assertions[1].outcome == want


@pytest.mark.parametrize("case", ["left", "right", "second_anchor", "overflow", "underflow"])
def test_absence_requires_entire_interval_for_every_anchor(case):
    manifest, events, profile, context = inputs()
    if case == "left": profile = change_rule(profile, 1, correlation=profile.rules[1].correlation.model_copy(update={"min_delta_ns": -2_000_000_000}))
    if case == "right": context = api.EvaluationContext(**(context.model_dump() | {"end": "2026-01-01T00:00:02Z"}))
    if case == "second_anchor": events.append(events[0].model_copy(update={"event_id": "late-anchor", "timestamp": "2026-01-01T00:00:59.000000001Z"}))
    if case in {"overflow", "underflow"}:
        timestamp = "9999-12-31T23:59:59Z" if case == "overflow" else "0001-01-01T00:00:00Z"
        events[0] = events[0].model_copy(update={"timestamp": timestamp})
        context = api.EvaluationContext(**(context.model_dump() | {"start": timestamp, "end": timestamp}))
        if case == "underflow": profile = change_rule(profile, 1, correlation=profile.rules[1].correlation.model_copy(update={"min_delta_ns": -1}))
    context = complete(profile, context, events)
    assert evaluate(manifest, events, profile, context).assertions[1].reason_code == "incomplete_detection_window"


def test_unknown_declaration_is_never_promoted_even_with_all_confirmation_metadata():
    manifest, events, profile, context = inputs()
    context = complete(profile, context, events, status="unknown")
    assertion = evaluate(manifest, events, profile, context).assertions[1]
    assert assertion.reason_code == "collection_not_confirmed"
    assert assertion.collection_assurance == "unknown"


def test_evidence_index_fingerprints_counts_and_manifest_order_are_deterministic():
    manifest, events, profile, context = inputs()
    events += [target(), target().model_copy(update={"event_id": "unknown", "hostname": None}),
               target().model_copy(update={"event_id": "excluded", "environment_id": "different"})]
    manifest = manifest.model_copy(update={"assertions": tuple(reversed(manifest.assertions))})
    profile = profile.model_copy(update={"scenario_fingerprint": api.scenario_fingerprint(manifest)})
    context = complete(profile, context, events)
    serializations = set()
    for permutation in itertools.permutations(events):
        result = evaluate(manifest, permutation, profile, context)
        serializations.add(result.model_dump_json())
    assert len(serializations) == 1
    assert tuple(a.assertion_id for a in result.assertions) == ("SCN-999-A02", "SCN-999-A01")
    assert result.counts.model_dump() == dict(satisfied=2, missing_telemetry=0, false_negative=0, inconclusive=0)
    assert result.scenario_fingerprint == api.scenario_fingerprint(manifest)
    assert result.profile_fingerprint == api.profile_fingerprint(profile)
    assert result.scope_fingerprint == api.scope_fingerprint(context)
    assert result.context_fingerprint == api.fingerprint(context)
    assert result.event_set_fingerprint == api.event_set_fingerprint(events)
    assert tuple(e.event_id for e in result.evidence_index) == ("activity", "detection", "unknown")
    for entry in result.evidence_index:
        assert entry.raw_event_ref == "synthetic/record:1"
        assert entry.raw_event_hash == "a" * 64
        assert entry.canonical_schema_version == "2.0"


def test_canonical_evidence_coordinates_are_preserved_without_predicate_text_budget():
    manifest, events, profile, context = inputs()
    identifier, reference = "synthetic-id-" + "a" * 4096, "synthetic/ref/" + "b" * 4096
    events[0] = events[0].model_copy(update={"event_id": identifier, "raw_event_ref": reference})
    events.append(target())
    result = evaluate(manifest, events, profile, context)
    assert result.final_status == "Detected"
    assert result.assertions[1].witness_pairs[0].anchor_event_id == identifier
    entry = next(entry for entry in result.evidence_index if entry.event_id == identifier)
    assert entry.raw_event_ref == reference


def test_long_valid_manifest_description_is_not_a_predicate_or_binding():
    manifest, events, profile, context = inputs()
    manifest = manifest.model_copy(update={"description": "Synthetic description " * 300})
    profile = profile.model_copy(update={"scenario_fingerprint": api.scenario_fingerprint(manifest)})
    events.append(target())
    assert evaluate(manifest, events, profile, context).final_status == "Detected"


def test_an_alert_does_not_hide_another_required_telemetry_branch():
    manifest, events, profile, context = inputs()
    events.append(target())
    extra = manifest.assertions[0].model_copy(update={"id": "SCN-999-A03"})
    manifest = manifest.model_copy(update={"assertions": manifest.assertions + (extra,)})
    rule = profile.rules[0].model_copy(update={"assertion_id": extra.id,
        "match": (api.Predicate(field="process_name", op="eq", value="another-process"),)})
    profile = profile.model_copy(update={"rules": profile.rules + (rule,), "scenario_fingerprint": api.scenario_fingerprint(manifest)})
    result = evaluate(manifest, events, profile, context)
    assert result.final_status == "Inconclusive"
    assert result.assertions[1].outcome == "satisfied"
    assert result.assertions[2].reason_code == "insufficient_fields"
    assert result.counts.satisfied == 2
    assert result.counts.inconclusive == 1


def test_unknown_anchor_join_field_is_referenced_as_unevaluable_evidence():
    manifest, events, profile, context = inputs()
    events.append(target(process_id=10))
    profile = change_rule(profile, 1, correlation=profile.rules[1].correlation.model_copy(update={
        "join_pairs": (api.JoinPair(target_field="process_id", anchor_field="process_id"),)}))
    assertion = evaluate(manifest, events, profile, context).assertions[1]
    assert assertion.reason_code == "insufficient_fields"
    assert assertion.evidence_ids == ("activity",)
    assert assertion.unevaluable_evidence_ids == ("activity", "detection")


def uncertain_activity_inputs():
    manifest, events, profile, context = inputs()
    events[0] = events[0].model_copy(update={"process_id": 1})
    events += [event(event_id="potential-activity", event_action=None, process_id=2, rule_id="different"),
               target(process_id=2)]
    profile = change_rule(profile, 1, correlation=profile.rules[1].correlation.model_copy(update={
        "join_pairs": (api.JoinPair(target_field="process_id", anchor_field="process_id"),)}))
    return manifest, events, profile, context


@pytest.mark.parametrize("unknown_target", [False, True])
def test_uncertain_activity_candidate_prevents_false_negative_even_with_satisfied_root(unknown_target):
    manifest, events, profile, context = uncertain_activity_inputs()
    if unknown_target:
        events[2] = events[2].model_copy(update={"rule_id": None})
    context = complete(profile, context, events)
    result = evaluate(manifest, events, profile, context)
    assert result.assertions[0].outcome == "satisfied"
    assert result.assertions[0].unevaluable_evidence_ids == ("potential-activity",)
    assert result.final_status == "Inconclusive"
    assertion = result.assertions[1]
    assert assertion.reason_code == "insufficient_fields"
    assert assertion.evidence_ids == ("activity",)
    assert assertion.witness_pairs == ()
    assert assertion.unevaluable_evidence_ids == ("detection", "potential-activity")
    assert tuple(entry.event_id for entry in result.evidence_index) == ("activity", "detection", "potential-activity")
    assert all(entry.raw_event_ref == "synthetic/record:1" for entry in result.evidence_index)
    assert all(entry.raw_event_hash == "a" * 64 for entry in result.evidence_index)
    assert evaluate(manifest, tuple(reversed(events)), profile, context).model_dump_json() == result.model_dump_json()


@pytest.mark.parametrize("known_false", ["join", "time", "scope"])
def test_known_false_eliminates_uncertain_activity_pair(known_false):
    manifest, events, profile, context = uncertain_activity_inputs()
    changes = {"join": {"process_id": 3}, "time": {"timestamp": "2026-01-01T00:00:00Z"},
               "scope": {"hostname": "different-host"}}[known_false]
    events[1] = events[1].model_copy(update=changes)
    context = complete(profile, context, events)
    result = evaluate(manifest, events, profile, context)
    assert result.final_status == "False negative"
    assert result.assertions[1].reason_code == "expected_detection_absent"
    assert result.assertions[1].unevaluable_evidence_ids == ()
    assert result.assertions[1].evidence_ids == ("activity",)


def test_positive_witness_wins_without_promoting_uncertain_activity_to_proof():
    manifest, events, profile, context = uncertain_activity_inputs()
    events.append(target(process_id=1).model_copy(update={"event_id": "known-detection"}))
    context = complete(profile, context, events)
    result = evaluate(manifest, events, profile, context)
    assert result.final_status == "Detected"
    assertion = result.assertions[1]
    assert assertion.evidence_ids == ("activity", "known-detection")
    assert assertion.witness_pairs == (api.WitnessPair(target_event_id="known-detection", anchor_event_id="activity"),)
    assert assertion.unevaluable_evidence_ids == ("detection", "potential-activity")


def test_uncertain_activity_candidate_cannot_correlate_to_itself():
    manifest, events, profile, context = uncertain_activity_inputs()
    events = events[:2]
    events[1] = events[1].model_copy(update={"rule_id": "synthetic-reviewed-rule"})
    context = complete(profile, context, events)
    result = evaluate(manifest, events, profile, context)
    assert result.final_status == "False negative"
    assert result.assertions[1].unevaluable_evidence_ids == ()
    assert result.assertions[1].witness_pairs == ()
