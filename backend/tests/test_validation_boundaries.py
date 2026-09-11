"""Public engine boundary tests using explicitly synthetic reviewed contracts."""
import pytest

import aegis_verify.validation as api
from aegis_verify.models.scenario import ScenarioManifest
from aegis_verify.models.precise_timestamp import PreciseTimestamp
from validation_cases import context_data, event, profile_data, rule_data


def inputs(*, role="detection", source="wazuh", expected="detected"):
    manifest = ScenarioManifest.model_validate(dict(
        id="SCN-999", name="Synthetic test", version="0.1.0", status="draft",
        description="Synthetic unit test only, not approved lab ground truth",
        safety=dict(destructive=False, authorization_required=True, notes="Synthetic only"),
        expected_sources=[source], expected_outcome=expected,
        assertions=[dict(id=f"SCN-999-A0{i}", description="Synthetic assertion", source=source) for i in (1, 2)],
    ))
    target = rule_data(assertion_id="SCN-999-A02", role=role,
        match=[dict(field="rule_id", op="eq", value="synthetic-reviewed-rule"), dict(field="event_action", op="eq", value="other")] if role == "detection" else
              [dict(field="event_action", op="eq", value="blocked")],
        correlation=dict(anchor_assertion_id="SCN-999-A01", join_pairs=[dict(target_field="hostname", anchor_field="hostname")],
                         min_delta_ns=0, max_delta_ns=1_000_000_000))
    root = rule_data(match=[dict(field="event_action", op="eq", value="observed")])
    if source in {"sysmon", "powershell"}:
        for rule in (root, target):
            rule["scope"] += [dict(field="event_provider", op="eq", value="synthetic-provider")]
    elif source != "wazuh":
        root["source_type"] = target["source_type"] = source
    profile = api.EvaluationProfile(**profile_data(scenario_fingerprint=api.scenario_fingerprint(manifest), rules=[root, target]))
    return manifest, [event(event_id="activity", event_action="observed")], profile, api.EvaluationContext(**context_data())


def evaluate(manifest, events, profile, context):
    return api.evaluate_scenario(manifest, events, profile=profile, context=context)


def complete(profile, context, events, **changes):
    declaration = dict(assertion_id="SCN-999-A02", status="complete_for_scope", confirmed_by="synthetic-reviewer",
        reference="synthetic-collection-report", coverage_start=context.start, coverage_end=context.end,
        no_sampling_or_truncation=True, no_parse_errors_or_gaps=True, clocks_adequate=True,
        profile_fingerprint=api.profile_fingerprint(profile), scope_fingerprint=api.scope_fingerprint(context),
        event_set_fingerprint=api.event_set_fingerprint(events)) | changes
    return context.model_copy(update={"declarations": (api.CollectionDeclaration(**declaration),)})


@pytest.mark.parametrize("position", range(4))
def test_rejects_non_contract_outer_input(position):
    args = list(inputs())
    args[position] = {"private-key": "private-value"}
    with pytest.raises(api.ValidationEngineError) as caught:
        evaluate(*args)
    assert caught.value.code == "invalid_input"
    assert "private" not in str(caught.value)


@pytest.mark.parametrize("kind,code", [
    ("iterator", "invalid_input"), ("duplicate", "duplicate_evidence_id"),
    ("v1", "unsupported_version"), ("event_version", "unsupported_version"),
    ("profile_version", "unsupported_version"), ("profile_id", "profile_binding"),
    ("scenario_version", "profile_binding"), ("fingerprint", "profile_binding"),
    ("missing_rule", "assertion_binding"), ("extra_rule", "assertion_binding"),
    ("source", "assertion_binding"), ("expected_role", "assertion_binding"),
    ("missing_binding", "missing_binding"), ("wrong_binding", "invalid_predicate"),
    ("nested_predicate", "invalid_predicate"), ("nested_join", "invalid_correlation"),
    ("nested_safety", "invalid_input"), ("event_integer", "invalid_input"),
    ("extra", "invalid_input"), ("timestamp", "invalid_input"), ("forged_timestamp", "invalid_input"),
    ("events_budget", "resource_limit"), ("scope_budget", "resource_limit"),
    ("bindings_budget", "resource_limit"), ("literal_budget", "resource_limit"),
])
def test_revalidates_inputs_before_any_evidence_evaluation(kind, code):
    manifest, events, profile, context = inputs()
    if kind == "iterator": events = iter(events)
    elif kind == "duplicate": events *= 2
    elif kind == "v1":
        from aegis_verify.models.canonical_event import CanonicalEvent
        events = [CanonicalEvent.model_validate(events[0].model_dump(mode="json") | {"schema_version": "1.0", "timestamp": "2026-01-01T00:00:01Z"})]
    elif kind == "event_version": events = [events[0].model_copy(update={"schema_version": "7.0"})]
    elif kind == "profile_version": profile = profile.model_copy(update={"profile_schema_version": "7.0.0"})
    elif kind == "profile_id": profile = profile.model_copy(update={"scenario_id": "SCN-998"})
    elif kind == "scenario_version": profile = profile.model_copy(update={"scenario_version": "0.2.0"})
    elif kind == "fingerprint": profile = profile.model_copy(update={"scenario_fingerprint": "b" * 64})
    elif kind == "missing_rule": profile = profile.model_copy(update={"rules": (profile.rules[0],)})
    elif kind == "extra_rule": profile = profile.model_copy(update={"rules": profile.rules + (profile.rules[0].model_copy(update={"assertion_id": "SCN-999-A03"}),)})
    elif kind == "source": profile = profile.model_copy(update={"rules": (profile.rules[0].model_copy(update={"source_type": "cowrie"}), profile.rules[1])})
    elif kind == "expected_role":
        manifest = manifest.model_copy(update={"expected_outcome": "prevented"})
        profile = profile.model_copy(update={"scenario_fingerprint": api.scenario_fingerprint(manifest)})
    elif kind == "missing_binding": context = context.model_copy(update={"bindings": ()})
    elif kind == "wrong_binding": context = context.model_copy(update={"bindings": (api.Binding(name="target", value=123),)})
    elif kind in {"nested_predicate", "scope_budget", "literal_budget"}:
        p = profile.rules[0].scope[0]
        scope = (p.model_copy(update={"op": "private-value"}),) if kind == "nested_predicate" else (p,) * 17 if kind == "scope_budget" else (p.model_copy(update={"binding": "x" * 4097}),)
        profile = profile.model_copy(update={"rules": (profile.rules[0].model_copy(update={"scope": scope}), profile.rules[1])})
    elif kind == "nested_join":
        corr = profile.rules[1].correlation.model_copy(update={"join_pairs": (api.JoinPair.model_construct(target_field="rule_id", anchor_field="hostname"),)})
        profile = profile.model_copy(update={"rules": (profile.rules[0], profile.rules[1].model_copy(update={"correlation": corr}))})
    elif kind == "nested_safety": manifest = manifest.model_copy(update={"safety": manifest.safety.model_copy(update={"destructive": True})})
    elif kind == "event_integer": events = [events[0].model_copy(update={"process_id": True})]
    elif kind == "extra": context = context.model_copy(update={"private-key": "private-value"})
    elif kind == "timestamp": events = [events[0].model_copy(update={"timestamp": "private-value"})]
    elif kind == "forged_timestamp":
        stamp = object.__new__(PreciseTimestamp)
        for key, value in (("_seconds", 0), ("_nanos", True), ("_digits", 9)): object.__setattr__(stamp, key, value)
        context = context.model_copy(update={"start": stamp})
    elif kind == "events_budget": events *= 10001
    elif kind == "bindings_budget": context = context.model_copy(update={"bindings": tuple(api.Binding(name=f"b{i}", value="x") for i in range(101))})
    with pytest.raises(api.ValidationEngineError) as caught:
        evaluate(manifest, events, profile, context)
    assert caught.value.code == code
    assert "private" not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("change", ["assertion", "role", "unsupported", "profile_hash", "scope_hash", "event_hash", "start", "end", "run", "binding"])
def test_collection_declaration_cannot_attest_different_inputs(change):
    manifest, events, profile, context = inputs()
    updates = {}
    if change == "assertion": updates["assertion_id"] = "SCN-999-A03"
    if change == "role": updates["assertion_id"] = "SCN-999-A01"
    for key, field in (("profile_hash", "profile_fingerprint"), ("scope_hash", "scope_fingerprint"), ("event_hash", "event_set_fingerprint")):
        if change == key: updates[field] = "b" * 64
    if change == "start": updates["coverage_start"] = "2026-01-01T00:00:00.000000001Z"
    if change == "end": updates["coverage_end"] = "2026-01-01T00:00:59.999999999Z"
    if change == "unsupported":
        profile = profile.model_copy(update={"rules": (profile.rules[0], api.AssertionRule(assertion_id="SCN-999-A02", role="detection", capability="unsupported", reason_code="requires_session_identity"))})
    context = complete(profile, context, events, **updates)
    if change == "run": context = context.model_copy(update={"run_id": "different-run"})
    if change == "binding": context = context.model_copy(update={"bindings": (api.Binding(name="target", value="different-host"),)})
    with pytest.raises(api.ValidationEngineError) as caught:
        evaluate(manifest, events, profile, context)
    assert caught.value.code == "invalid_collection_declaration"


@pytest.mark.parametrize("kind,code", [("duplicate_rules", "assertion_binding"),
    ("unknown_anchor", "invalid_correlation"), ("unsupported_anchor", "invalid_correlation"),
    ("declaration_flags", "invalid_collection_declaration"), ("event_deleted_version", "invalid_input")])
def test_constructed_cross_contract_errors_stay_classified_and_safe(kind, code):
    manifest, events, profile, context = inputs()
    if kind == "duplicate_rules": profile = profile.model_copy(update={"rules": profile.rules + (profile.rules[0],)})
    elif kind == "unknown_anchor":
        correlation = profile.rules[1].correlation.model_copy(update={"anchor_assertion_id": "private-value"})
        profile = profile.model_copy(update={"rules": (profile.rules[0], profile.rules[1].model_copy(update={"correlation": correlation}))})
    elif kind == "unsupported_anchor":
        profile = profile.model_copy(update={"rules": (api.AssertionRule(assertion_id="SCN-999-A01", role="telemetry", capability="unsupported", reason_code="requires_session_identity"), profile.rules[1])})
    elif kind == "declaration_flags":
        context = complete(profile, context, events)
        context = context.model_copy(update={"declarations": (context.declarations[0].model_copy(update={"clocks_adequate": False}),)})
    else:
        events[0].__dict__.pop("schema_version")
    with pytest.raises(api.ValidationEngineError) as caught:
        evaluate(manifest, events, profile, context)
    assert caught.value.code == code
    assert "private" not in str(caught.value)


def test_global_comparison_budget_accepts_exact_million_and_rejects_next_pair():
    manifest, events, profile, context = inputs()
    # 99 roots plus 1 target each evaluate 10,000 scoped events: 1,000,000.
    # Initially every target fails a known literal, so no join pairs are tried.
    assertions = tuple(manifest.assertions[0].model_copy(update={"id": f"SCN-999-A{i:02}"}) for i in range(100))
    manifest = manifest.model_copy(update={"assertions": assertions})
    roots = tuple(profile.rules[0].model_copy(update={"assertion_id": assertion.id}) for assertion in assertions[:-1])
    detection = profile.rules[1].model_copy(update={"assertion_id": "SCN-999-A99", "match": (profile.rules[1].match[0],)})
    profile = profile.model_copy(update={"rules": roots + (detection,), "scenario_fingerprint": api.scenario_fingerprint(manifest)})
    events = [events[0].model_copy(update={"event_id": f"e{i:05}", "rule_id": "different"}) for i in range(10000)]
    result = evaluate(manifest, events, profile, context)
    assert result.counts.satisfied == 99
    assert result.assertions[-1].reason_code == "collection_not_confirmed"
    # Last candidate now enters its first non-self pair after comparison 1,000,000.
    events[-1] = events[-1].model_copy(update={"rule_id": "synthetic-reviewed-rule"})
    with pytest.raises(api.ValidationEngineError) as caught:
        evaluate(manifest, events, profile, context)
    assert caught.value.code == "resource_limit"


def test_unserializable_integer_is_a_safe_public_error():
    manifest, events, profile, context = inputs()
    events[0] = events[0].model_copy(update={"process_id": 10 ** 5000})
    for operation in (lambda: evaluate(manifest, events, profile, context), lambda: api.event_set_fingerprint(events)):
        with pytest.raises(api.ValidationEngineError) as caught:
            operation()
        assert caught.value.code == "invalid_input"
        assert caught.value.__cause__ is None


@pytest.mark.parametrize("dimension", ["match", "rules", "declarations", "values", "join_pairs"])
def test_nested_resource_overruns_are_classified_before_evaluation(dimension):
    manifest, events, profile, context = inputs()
    if dimension == "match":
        root = profile.rules[0].model_copy(update={"match": (profile.rules[0].match[0],) * 17})
        profile = profile.model_copy(update={"rules": (root, profile.rules[1])})
    elif dimension == "rules": profile = profile.model_copy(update={"rules": (profile.rules[0],) * 101})
    elif dimension == "declarations": context = context.model_copy(update={"declarations": tuple(api.CollectionDeclaration(assertion_id=f"a{i}") for i in range(101))})
    elif dimension == "values":
        predicate = api.Predicate.model_construct(field="rule_id", op="in", values=("synthetic-id",) * 101)
        profile = profile.model_copy(update={"rules": (profile.rules[0], profile.rules[1].model_copy(update={"match": (predicate,)}))})
    else:
        correlation = profile.rules[1].correlation.model_copy(update={"join_pairs": profile.rules[1].correlation.join_pairs * 9})
        profile = profile.model_copy(update={"rules": (profile.rules[0], profile.rules[1].model_copy(update={"correlation": correlation}))})
    with pytest.raises(api.ValidationEngineError) as caught:
        evaluate(manifest, events, profile, context)
    assert caught.value.code == "resource_limit"


def test_unknown_declaration_still_rejects_mismatched_supplied_hash():
    manifest, events, profile, context = inputs()
    context = context.model_copy(update={"declarations": (api.CollectionDeclaration(assertion_id="SCN-999-A02", event_set_fingerprint="b" * 64),)})
    with pytest.raises(api.ValidationEngineError) as caught:
        evaluate(manifest, events, profile, context)
    assert caught.value.code == "invalid_collection_declaration"


def test_missing_binding_is_preflighted_even_when_anchor_and_event_set_are_missing():
    manifest, _, profile, context = inputs()
    missing = api.Predicate(field="process_id", op="eq", binding="missing-process")
    profile = profile.model_copy(update={"rules": (profile.rules[0], profile.rules[1].model_copy(update={"match": profile.rules[1].match + (missing,)}))})
    with pytest.raises(api.ValidationEngineError) as caught:
        evaluate(manifest, [], profile, context)
    assert caught.value.code == "missing_binding"
