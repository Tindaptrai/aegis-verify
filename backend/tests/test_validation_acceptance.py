"""Issue 7 public acceptance tests; profiles and verdicts remain synthetic."""

import subprocess
import sys
from pathlib import Path

import pytest

import aegis_verify.validation as api
from aegis_verify.connectors.cowrie import parse_cowrie_jsonl
from aegis_verify.models import CanonicalEventV2
from aegis_verify.models.scenario import ScenarioManifest


FIXTURES = Path(__file__).resolve().parents[2] / "tests/fixtures/cowrie/native"
GUIDE = Path(__file__).resolve().parents[2] / "docs/VALIDATION_ENGINE.md"


def _manifest(*, scenario_id="SCN-999", source="wazuh"):
    return ScenarioManifest.model_validate({
        "id": scenario_id,
        "name": "Synthetic validation acceptance",
        "version": "0.1.0",
        "status": "draft",
        "description": "Synthetic API exercise only; not approved lab ground truth.",
        "safety": {
            "destructive": False,
            "authorization_required": True,
            "notes": "Does not execute an action.",
        },
        "expected_sources": [source],
        "expected_outcome": "detected",
        "assertions": [
            {"id": f"{scenario_id}-A01", "description": "Synthetic activity", "source": source},
            {"id": f"{scenario_id}-A02", "description": "Synthetic detection", "source": source},
        ],
    })


def _event(event_id, *, timestamp, **changes):
    values = {
        "event_id": event_id,
        "source_type": "wazuh",
        "environment_id": "synthetic-env",
        "timestamp": timestamp,
        "ingested_at": "2026-01-01T00:00:03Z",
        "hostname": "synthetic-host",
        "raw_event_ref": f"synthetic-only/{event_id}:1",
        "raw_event_hash": ("a" if event_id == "activity" else "b") * 64,
    }
    return CanonicalEventV2.model_validate(values | changes)


def _inputs():
    manifest = _manifest()
    scope = (api.Predicate(field="hostname", op="eq", binding="target_host"),)
    profile = api.EvaluationProfile(
        profile_id="synthetic-acceptance",
        profile_version="0.1.0",
        scenario_id=manifest.id,
        scenario_version=manifest.version,
        scenario_fingerprint=api.scenario_fingerprint(manifest),
        rules=(
            api.AssertionRule(
                assertion_id="SCN-999-A01",
                role="telemetry",
                capability="supported",
                source_type="wazuh",
                scope=scope,
                match=(api.Predicate(field="event_action", op="eq", value="observed"),),
            ),
            api.AssertionRule(
                assertion_id="SCN-999-A02",
                role="detection",
                capability="supported",
                source_type="wazuh",
                scope=scope,
                match=(api.Predicate(field="rule_id", op="eq", value="synthetic-rule"),),
                correlation=api.Correlation(
                    anchor_assertion_id="SCN-999-A01",
                    join_pairs=(api.JoinPair(target_field="hostname", anchor_field="hostname"),),
                    min_delta_ns=0,
                    max_delta_ns=1_000_000_000,
                ),
            ),
        ),
    )
    context = api.EvaluationContext(
        run_id="synthetic-run",
        environment_id="synthetic-env",
        start="2026-01-01T00:00:00Z",
        end="2026-01-01T00:00:10Z",
        bindings=(api.Binding(name="target_host", value="synthetic-host"),),
    )
    events = [
        _event("activity", timestamp="2026-01-01T00:00:01.000000001Z", event_action="observed"),
        _event(
            "alert",
            timestamp="2026-01-01T00:00:02.000000001Z",
            event_action="other",
            rule_id="synthetic-rule",
        ),
    ]
    return manifest, events, profile, context


def _evaluate(manifest, events, profile, context):
    return api.evaluate_scenario(manifest, events, profile=profile, context=context)


def test_public_api_detects_exact_pair_without_mutating_inputs_or_inventing_evidence():
    manifest, events, profile, context = _inputs()
    before = (
        manifest.model_dump_json(),
        tuple(event.model_dump_json() for event in events),
        profile.model_dump_json(),
        context.model_dump_json(),
        tuple(event.event_id for event in events),
    )

    result = _evaluate(manifest, events, profile, context)

    assert result.final_status == "Detected"
    assert result.assertions[1].witness_pairs == (
        api.WitnessPair(target_event_id="alert", anchor_event_id="activity"),
    )
    input_ids = {event.event_id for event in events}
    referenced_ids = {
        identifier
        for assertion in result.assertions
        for identifier in assertion.evidence_ids + assertion.unevaluable_evidence_ids
    } | {
        identifier
        for assertion in result.assertions
        for pair in assertion.witness_pairs
        for identifier in (pair.target_event_id, pair.anchor_event_id)
    }
    assert referenced_ids <= input_ids
    assert {entry.event_id for entry in result.evidence_index} == referenced_ids
    assert before == (
        manifest.model_dump_json(),
        tuple(event.model_dump_json() for event in events),
        profile.model_dump_json(),
        context.model_dump_json(),
        tuple(event.event_id for event in events),
    )


def test_duplicate_event_id_is_rejected_even_when_duplicate_is_outside_scope():
    manifest, events, profile, context = _inputs()
    events[1] = events[0].model_copy(update={
        "environment_id": "outside-environment",
        "timestamp": "2027-01-01T00:00:00Z",
    })

    with pytest.raises(api.ValidationEngineError) as caught:
        _evaluate(manifest, events, profile, context)

    assert caught.value.code == "duplicate_evidence_id"
    assert caught.value.path == ("events",)


def test_forged_nested_secret_key_is_revalidated_and_never_echoed():
    manifest, events, profile, context = _inputs()
    forged = profile.rules[0].scope[0].model_copy(
        update={"secret-looking-key": "do-not-echo-this-token"}
    )
    profile = profile.model_copy(update={
        "rules": (
            profile.rules[0].model_copy(update={"scope": (forged,)}),
            profile.rules[1],
        )
    })

    with pytest.raises(api.ValidationEngineError) as caught:
        _evaluate(manifest, events, profile, context)

    assert caught.value.code == "invalid_predicate"
    assert caught.value.__cause__ is None
    assert "secret-looking-key" not in str(caught.value)
    assert "do-not-echo-this-token" not in str(caught.value)


@pytest.mark.parametrize("case", ["partial_complete", "wrong_hash"])
def test_untrusted_collection_attestation_is_rejected_before_a_verdict(case):
    manifest, events, profile, context = _inputs()
    if case == "partial_complete":
        declaration = api.CollectionDeclaration.model_construct(
            assertion_id="SCN-999-A02",
            status="complete_for_scope",
            confirmed_by="synthetic-reviewer",
            reference="synthetic-only/collection-report",
            coverage_start=context.start,
            coverage_end=context.end,
            no_sampling_or_truncation=True,
            no_parse_errors_or_gaps=True,
            clocks_adequate=True,
            profile_fingerprint=api.profile_fingerprint(profile),
            scope_fingerprint=api.scope_fingerprint(context),
        )
    else:
        declaration = api.CollectionDeclaration(
            assertion_id="SCN-999-A02",
            status="unknown",
            event_set_fingerprint="f" * 64,
        )
    context = context.model_copy(update={"declarations": (declaration,)})

    with pytest.raises(api.ValidationEngineError) as caught:
        _evaluate(manifest, events[:1], profile, context)

    assert caught.value.code == "invalid_collection_declaration"
    assert caught.value.__cause__ is None


def test_partial_unknown_attestation_never_becomes_false_negative():
    manifest, events, profile, context = _inputs()
    declaration = api.CollectionDeclaration(
        assertion_id="SCN-999-A02",
        status="unknown",
        confirmed_by="synthetic-reviewer",
        reference="synthetic-only/partial-collection-note",
        coverage_start=context.start,
        coverage_end=context.end,
        no_sampling_or_truncation=True,
        no_parse_errors_or_gaps=True,
        clocks_adequate=True,
    )
    context = context.model_copy(update={"declarations": (declaration,)})

    result = _evaluate(manifest, events[:1], profile, context)

    assert result.final_status == "Inconclusive"
    assert result.assertions[1].reason_code == "collection_not_confirmed"
    assert result.assertions[1].collection_assurance == "unknown"


def test_one_pair_cannot_cross_mix_and_positive_witness_wins_over_unknown_anchor():
    manifest, events, profile, context = _inputs()
    events = [
        events[0].model_copy(update={"event_id": "anchor-a", "process_id": 1, "src_port": 10}),
        events[0].model_copy(update={"event_id": "anchor-b", "process_id": 2, "src_port": 20}),
        events[0].model_copy(update={
            "event_id": "uncertain-anchor", "event_action": None, "process_id": 3, "src_port": 30,
        }),
        events[1].model_copy(update={"event_id": "cross-mix", "process_id": 1, "src_port": 20}),
        events[1].model_copy(update={"event_id": "positive", "process_id": 2, "src_port": 20}),
        events[1].model_copy(update={"event_id": "unknown-target", "process_id": 3, "src_port": 30}),
    ]
    correlation = profile.rules[1].correlation.model_copy(update={
        "join_pairs": (
            api.JoinPair(target_field="process_id", anchor_field="process_id"),
            api.JoinPair(target_field="src_port", anchor_field="src_port"),
        )
    })
    profile = profile.model_copy(update={
        "rules": (
            profile.rules[0],
            profile.rules[1].model_copy(update={"correlation": correlation}),
        )
    })

    result = _evaluate(manifest, events, profile, context)
    detection = result.assertions[1]

    assert result.final_status == "Detected"
    assert detection.witness_pairs == (
        api.WitnessPair(target_event_id="positive", anchor_event_id="anchor-b"),
    )
    assert detection.evidence_ids == ("anchor-b", "positive")
    assert detection.unevaluable_evidence_ids == ("uncertain-anchor", "unknown-target")
    assert "cross-mix" not in detection.evidence_ids + detection.unevaluable_evidence_ids


def test_sanitized_cowrie_output_is_canonical_input_but_session_requirement_stays_unsupported():
    fixture = FIXTURES / "session-sequence.sanitized.jsonl"
    records = parse_cowrie_jsonl(
        fixture.read_bytes(),
        source_ref="synthetic-acceptance-cowrie",
        environment_id="native-fixture-lab",
        sensor_id="cowrie-native-fixture-01",
        ingested_at="2026-09-11T04:39:42Z",
    )
    events = [record.event for record in records if record.event is not None]
    manifest = _manifest(scenario_id="SCN-998", source="cowrie")
    profile = api.EvaluationProfile(
        profile_id="synthetic-cowrie-compatibility",
        profile_version="0.1.0",
        scenario_id=manifest.id,
        scenario_version=manifest.version,
        scenario_fingerprint=api.scenario_fingerprint(manifest),
        rules=(
            api.AssertionRule(
                assertion_id="SCN-998-A01",
                role="telemetry",
                capability="supported",
                source_type="cowrie",
                scope=(api.Predicate(field="src_ip", op="eq", binding="synthetic_actor_ip"),),
                match=(api.Predicate(field="event_action", op="eq", value="observed"),),
            ),
            api.AssertionRule(
                assertion_id="SCN-998-A02",
                role="detection",
                capability="unsupported",
                reason_code="requires_session_identity",
            ),
        ),
    )
    context = api.EvaluationContext(
        run_id="synthetic-cowrie-intake",
        environment_id="native-fixture-lab",
        start="2026-04-16T15:16:04Z",
        end="2026-04-16T15:16:31Z",
        bindings=(api.Binding(name="synthetic_actor_ip", value="198.51.100.20"),),
    )

    result = _evaluate(manifest, events, profile, context)

    assert result.final_status == "Inconclusive"
    assert result.assertions[0].outcome == "satisfied"
    assert result.assertions[1].reason_code == "unsupported_requirement"
    assert result.assertions[1].evidence_ids == ()
    by_id = {event.event_id: event for event in events}
    assert result.evidence_index
    assert all(entry.event_id in by_id for entry in result.evidence_index)
    assert all(
        (entry.raw_event_ref, entry.raw_event_hash)
        == (by_id[entry.event_id].raw_event_ref, by_id[entry.event_id].raw_event_hash)
        for entry in result.evidence_index
    )


def test_public_boundary_rejects_more_than_one_hundred_manifest_assertions():
    manifest, events, profile, context = _inputs()
    manifest = manifest.model_copy(update={
        "assertions": manifest.assertions + (manifest.assertions[0],) * 99,
    })

    with pytest.raises(api.ValidationEngineError) as caught:
        _evaluate(manifest, events, profile, context)

    assert caught.value.code == "resource_limit"
    assert caught.value.path == ("manifest", "assertions")


def test_documented_synthetic_program_runs_with_the_documented_output(tmp_path):
    document = GUIDE.read_text(encoding="utf-8")
    example = document.split("<!-- runnable-example:start -->", 1)[1].split(
        "<!-- runnable-example:end -->", 1
    )[0]
    program = example.split("```python\n", 1)[1].split("\n```", 1)[0]

    completed = subprocess.run(
        [sys.executable, "-"],
        input=program,
        text=True,
        capture_output=True,
        cwd=tmp_path,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert completed.stdout == (
        "Detected\n"
        "(WitnessPair(target_event_id='synthetic-alert', "
        "anchor_event_id='synthetic-activity'),)\n"
        "False negative\n"
        "caller-attested\n"
    )
