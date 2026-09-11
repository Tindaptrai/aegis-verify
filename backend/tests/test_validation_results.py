"""Deterministic fingerprints/results from synthetic contracts."""
import hashlib
import importlib
import itertools
import json
import pytest
from pydantic import ValidationError
from aegis_verify.validation.contracts import EvaluationContext, EvaluationProfile
from aegis_verify.validation.errors import ValidationEngineError
from validation_cases import context_data, event, profile_data


def results():
    return importlib.import_module("aegis_verify.validation.results")


def test_hash_is_standard_json_with_defaults_nulls_and_exact_timestamps():
    r = results()
    value = event()
    expected = hashlib.sha256(json.dumps(value.model_dump(mode="json"), sort_keys=True,
        separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
    assert r.fingerprint(value) == expected
    assert r.fingerprint(value) != r.fingerprint(event(timestamp="2026-01-01T00:00:01.000000010Z"))
    assert r.fingerprint(event(timestamp="2026-01-01T00:00:01.0Z")) != r.fingerprint(event(timestamp="2026-01-01T00:00:01.00Z"))


def test_event_set_order_duplicates_and_limits():
    r = results()
    a, b = event(event_id="a"), event(event_id="b")
    assert r.event_set_fingerprint([a, b]) == r.event_set_fingerprint((b, a))
    for values, code in (([a, a], "duplicate_evidence_id"), (iter([a]), "invalid_input")):
        with pytest.raises(ValidationEngineError) as caught:
            r.event_set_fingerprint(values)
        assert caught.value.code == code
    values = [event(event_id=f"synthetic-{i}") for i in range(10000)]
    assert len(r.event_set_fingerprint(values)) == 64
    with pytest.raises(ValidationEngineError) as caught:
        r.event_set_fingerprint(values + [event(event_id="extra")])
    assert caught.value.code == "resource_limit"


def test_scope_excludes_declarations_but_context_includes_them():
    r = results()
    context = EvaluationContext(**context_data())
    changed = EvaluationContext(**context_data(declarations=[dict(assertion_id="SCN-999-A01")]))
    assert r.scope_fingerprint(context) == r.scope_fingerprint(changed)
    assert r.fingerprint(context) != r.fingerprint(changed)
    assert r.scope_fingerprint(context) != r.scope_fingerprint(EvaluationContext(**context_data(run_id="different")))


@pytest.mark.parametrize("kind", ["copy", "construct", "nested", "extra", "timestamp", "wrong_model"])
def test_fingerprints_revalidate_without_laundering(kind):
    r = results()
    from aegis_verify.models.precise_timestamp import PreciseTimestamp
    value = EvaluationProfile(**profile_data())
    if kind == "copy":
        value = value.model_copy(update={"profile_version": 123})
    elif kind == "construct":
        value = EvaluationProfile.model_construct(**(profile_data() | {"profile_schema_version": "9.0.0"}))
    elif kind == "nested":
        value = value.model_copy(update={"rules": (value.rules[0].model_copy(update={"source_type": "sysmon"}),)})
    elif kind == "extra":
        value = value.model_copy(update={"secret-arbitrary-key": "private-value"})
    elif kind == "timestamp":
        stamp = object.__new__(PreciseTimestamp)
        for name, component in (("_seconds", 0), ("_nanos", True), ("_digits", 9)):
            object.__setattr__(stamp, name, component)
        value = event().model_copy(update={"timestamp": stamp})
    else:
        value = {"profile": "arbitrary"}
    with pytest.raises(ValidationEngineError) as caught:
        r.fingerprint(value)
    assert "private-value" not in str(caught.value)
    assert "secret-arbitrary-key" not in str(caught.value)


def test_aggregate_every_outcome_combination():
    r = results()
    for outcomes in itertools.product(("satisfied", "missing_telemetry", "false_negative", "inconclusive"), repeat=3):
        expected = ("Inconclusive" if "inconclusive" in outcomes else "Missing telemetry" if "missing_telemetry" in outcomes
                    else "False negative" if "false_negative" in outcomes else "Detected")
        assert r.aggregate_status("detected", outcomes) == expected
    assert r.aggregate_status("prevented", ("satisfied",)) == "Prevented"
    for outcomes in ((), ("unknown",)):
        with pytest.raises(ValidationEngineError):
            r.aggregate_status("detected", outcomes)


def test_result_evidence_is_sorted_frozen_and_counted():
    r = results()
    assertion = r.AssertionResult(assertion_id="SCN-999-A01", role="detection", outcome="satisfied", reason_code="witness_found",
        evidence_ids=["b", "a", "a"], unevaluable_evidence_ids=["z", "c"],
        witness_pairs=[dict(target_event_id="b", anchor_event_id="a"), dict(target_event_id="a", anchor_event_id="b")])
    assert assertion.evidence_ids == ("a", "b")
    assert assertion.unevaluable_evidence_ids == ("c", "z")
    assert assertion.witness_pairs[0].target_event_id == "a"
    assert assertion.collection_assurance == "unknown"
    with pytest.raises(ValidationError):
        assertion.evidence_ids = ()
    entries = r.build_evidence_index([event(event_id="b"), event(event_id="a")], ("b", "a"))
    assert tuple(e.event_id for e in entries) == ("a", "b")
    assert entries[0].raw_event_hash == "a" * 64
    assert entries[0].canonical_schema_version == "2.0"
    with pytest.raises(ValidationEngineError):
        r.build_evidence_index([event()], ("invented",))
    counts = r.count_outcomes((assertion,))
    assert counts.model_dump() == dict(satisfied=1, missing_telemetry=0, false_negative=0, inconclusive=0)
    result = r.EvaluationResult(run_id="synthetic-run", scenario_id="SCN-999", scenario_version="0.1.0",
        profile_id="synthetic-profile", profile_version="0.1.0", scenario_fingerprint="a"*64,
        profile_fingerprint="b"*64, scope_fingerprint="c"*64, context_fingerprint="d"*64, event_set_fingerprint="e"*64,
        final_status="Detected", assertions=[assertion], counts=counts, evidence_index=list(reversed(entries)))
    assert result.evidence_index[0].event_id == "a"
    assert json.loads(result.model_dump_json())["result_schema_version"] == "0.1.0"
    with pytest.raises(ValidationError):
        result.final_status = "Prevented"


def test_safe_error_paths_do_not_echo_arbitrary_keys():
    error = ValidationEngineError("invalid_input", ("events", 1, "secret-key"))
    assert error.path == ("events", 1, "input")
    assert "secret-key" not in str(error)
