"""Contract limits and invariants on explicitly synthetic profiles."""
import importlib
import pytest
from pydantic import ValidationError
from validation_cases import context_data, profile_data, rule_data


@pytest.fixture
def c():
    return importlib.import_module("aegis_verify.validation.contracts")


def test_contracts_are_frozen_ordered_and_strict(c):
    profile = c.EvaluationProfile(**profile_data())
    assert isinstance(profile.rules, tuple)
    assert isinstance(profile.rules[0].scope, tuple)
    with pytest.raises(ValidationError):
        profile.rules[0].scope = ()
    for changes in ({"extra": 1}, {"profile_schema_version": "9.0.0"}, {"rules": iter([])}, {"rules": []}):
        with pytest.raises(ValidationError):
            c.EvaluationProfile(**profile_data(**changes))


@pytest.mark.parametrize("changes", [
    {"source_type": None}, {"scope": []}, {"role": "detection"},
    {"capability": "unsupported"}, {"reason_code": "unneeded"},
    {"scope": [{"field": "hostname", "op": "eq", "value": "host"}]},
])
def test_supported_rule_obligations(c, changes):
    with pytest.raises(ValidationError):
        c.AssertionRule(**rule_data(**changes))


def test_unsupported_rule_has_only_explicit_reason(c):
    assert c.AssertionRule(assertion_id="SCN-999-A01", role="detection", capability="unsupported",
                           reason_code="requires_session_identity").scope == ()
    with pytest.raises(ValidationError):
        c.AssertionRule(**rule_data(capability="unsupported", reason_code="requires_session_identity"))


@pytest.mark.parametrize("changes", [
    {"start": "2026-01-02T00:00:00Z"}, {"run_id": 1}, {"bindings": iter([])},
    {"bindings": [{"name": "x", "value": 1}, {"name": "x", "value": 2}]},
    {"start": "0000-01-01T00:00:00Z"},
])
def test_context_rejects_invalid_scope(c, changes):
    with pytest.raises(ValidationError):
        c.EvaluationContext(**context_data(**changes))


def test_complete_collection_requires_metadata_and_true_confirmations(c):
    data = dict(assertion_id="SCN-999-A01", status="complete_for_scope", confirmed_by="synthetic-reviewer",
                reference="synthetic-attestation", coverage_start="2026-01-01T00:00:00Z",
                coverage_end="2026-01-01T00:01:00Z", no_sampling_or_truncation=True,
                no_parse_errors_or_gaps=True, clocks_adequate=True, profile_fingerprint="a"*64,
                scope_fingerprint="b"*64, event_set_fingerprint="c"*64)
    assert c.CollectionDeclaration(**data).status == "complete_for_scope"
    for key in set(data) - {"assertion_id", "status"}:
        with pytest.raises(ValidationError):
            c.CollectionDeclaration(**(data | {key: None}))
    with pytest.raises(ValidationError):
        c.CollectionDeclaration(**(data | {"clocks_adequate": False}))
    assert c.CollectionDeclaration(**(data | {"status": "unknown"})).status == "unknown"
    assert c.CollectionDeclaration(assertion_id="SCN-999-A01", no_sampling_or_truncation=True).status == "unknown"


def test_model_collection_limits(c):
    for field in ("scope", "match"):
        conditions = [dict(field="hostname", op="eq", binding="target")] * 16
        assert len(getattr(c.AssertionRule(**rule_data(**{field: conditions})), field)) == 16
        with pytest.raises(ValidationError):
            c.AssertionRule(**rule_data(**{field: conditions + conditions[:1]}))
    bindings = [dict(name=f"b{i}", value=i) for i in range(100)]
    assert len(c.EvaluationContext(**context_data(bindings=bindings)).bindings) == 100
    with pytest.raises(ValidationError):
        c.EvaluationContext(**context_data(bindings=bindings + [dict(name="extra", value=1)]))
    rules = [rule_data(assertion_id=f"synthetic-{i}") for i in range(100)]
    assert len(c.EvaluationProfile(**profile_data(rules=rules)).rules) == 100
    with pytest.raises(ValidationError):
        c.EvaluationProfile(**profile_data(rules=rules + [rule_data(assertion_id="extra")]))


def test_profile_anchor_and_role_obligations(c):
    corr = dict(anchor_assertion_id="SCN-999-A01", join_pairs=[dict(target_field="hostname", anchor_field="hostname")],
                min_delta_ns=-1, max_delta_ns=1)
    detection = rule_data(assertion_id="SCN-999-A02", role="detection", correlation=corr,
                          match=[dict(field="rule_id", op="in", values=["reviewed-rule"])])
    assert len(c.EvaluationProfile(**profile_data(rules=[rule_data(), detection])).rules) == 2
    for changes in ({"match": []}, {"match": [{"field": "rule_id", "op": "exists"}]},
                    {"correlation": None}):
        with pytest.raises(ValidationError):
            c.AssertionRule(**(detection | changes))
    with pytest.raises(ValidationError):
        c.EvaluationProfile(**profile_data(rules=[detection]))
    for action in ("allowed", "redirected"):
        with pytest.raises(ValidationError):
            c.AssertionRule(**(detection | dict(role="prevention", match=[dict(field="event_action", op="eq", value=action)])))
    assert c.AssertionRule(**(detection | dict(role="prevention", match=[dict(field="event_action", op="eq", value="blocked")]))).role == "prevention"


def test_logical_sources_require_explicit_provider_without_guessing(c):
    from aegis_verify.validation.errors import ValidationEngineError
    telemetry = c.AssertionRule(**rule_data())
    c.validate_rule_source(telemetry, "wazuh")
    for source in ("sysmon", "powershell", "cowrie"):
        with pytest.raises(ValidationEngineError) as caught:
            c.validate_rule_source(telemetry, source)
        assert caught.value.code == "assertion_binding"
    for source in ("sysmon", "powershell"):
        mapped = c.AssertionRule(**rule_data(scope=rule_data()["scope"] + [dict(field="event_provider", op="eq", value="reviewed-provider")]))
        c.validate_rule_source(mapped, source)
    with pytest.raises(ValidationError):
        c.EvaluationProfile(**profile_data(rules=[rule_data(), rule_data()]))


def test_snort_is_a_closed_set_source_for_rules_and_predicates(c):
    from aegis_verify.validation.errors import ValidationEngineError
    snort = c.AssertionRule(**rule_data(source_type="snort"))
    c.validate_rule_source(snort, "snort")
    for source in ("suricata", "wazuh"):
        with pytest.raises(ValidationEngineError) as caught:
            c.validate_rule_source(snort, source)
        assert caught.value.code == "assertion_binding"
    scoped = rule_data(scope=rule_data()["scope"] + [dict(field="source_type", op="eq", value="snort")])
    assert c.AssertionRule(**scoped).scope[-1].value == "snort"
    for unknown in ("snort3", "Snort"):
        with pytest.raises(ValidationError):
            c.AssertionRule(**rule_data(source_type=unknown))


def test_opnsense_is_a_closed_set_source_separate_from_pfsense(c):
    from aegis_verify.validation.errors import ValidationEngineError
    opnsense = c.AssertionRule(**rule_data(source_type="opnsense"))
    c.validate_rule_source(opnsense, "opnsense")
    for source in ("pfsense", "snort"):
        with pytest.raises(ValidationEngineError) as caught:
            c.validate_rule_source(opnsense, source)
        assert caught.value.code == "assertion_binding"
    scoped = rule_data(scope=rule_data()["scope"] + [dict(field="source_type", op="eq", value="opnsense")])
    assert c.AssertionRule(**scoped).scope[-1].value == "opnsense"
    for unknown in ("OPNsense", "opnsense-filterlog"):
        with pytest.raises(ValidationError):
            c.AssertionRule(**rule_data(source_type=unknown))


def test_binding_and_declaration_lists_accept_limit_reject_next(c):
    declarations = [dict(assertion_id=f"synthetic-{i}") for i in range(100)]
    assert len(c.EvaluationContext(**context_data(declarations=declarations)).declarations) == 100
    with pytest.raises(ValidationError):
        c.EvaluationContext(**context_data(declarations=declarations + [dict(assertion_id="extra")]))
    with pytest.raises(ValidationError):
        c.EvaluationContext(**context_data(declarations=declarations[:1] * 2))


@pytest.mark.parametrize("field", ["rule_id", "signature_id"])
@pytest.mark.parametrize("op", ["eq", "in"])
@pytest.mark.parametrize("location", ["scope", "match"])
def test_detection_ids_must_be_fixed_in_reviewed_profile(c, field, op, location):
    data = rule_data(role="detection", correlation=dict(
        anchor_assertion_id="SCN-999-A02",
        join_pairs=[dict(target_field="hostname", anchor_field="hostname")],
        min_delta_ns=0, max_delta_ns=1,
    ))
    existing = data.get(location, [])
    data[location] = existing + [dict(field=field, op=op, binding="runtime_rule")]
    with pytest.raises(ValidationError):
        c.AssertionRule(**data)

    operand = dict(value="reviewed-rule") if op == "eq" else dict(values=["reviewed-rule"])
    data[location] = existing + [dict(field=field, op=op, **operand)]
    assert c.AssertionRule(**data).role == "detection"
