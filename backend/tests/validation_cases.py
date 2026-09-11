"""Synthetic validation inputs only; no approved lab ground truth."""

from aegis_verify.models import CanonicalEventV2


def event(**changes):
    return CanonicalEventV2.model_validate(dict(
        event_id="synthetic-event", timestamp="2026-01-01T00:00:01.000000001Z",
        ingested_at="2026-01-01T00:00:02Z", source_type="wazuh",
        environment_id="synthetic-lab", raw_event_ref="synthetic/record:1",
        raw_event_hash="a" * 64, hostname="synthetic-host",
    ) | changes)


def rule_data(**changes):
    return dict(assertion_id="SCN-999-A01", role="telemetry", capability="supported",
                source_type="wazuh", scope=[dict(field="hostname", op="eq", binding="target")]) | changes


def context_data(**changes):
    return dict(run_id="synthetic-run", environment_id="synthetic-lab",
                start="2026-01-01T00:00:00Z", end="2026-01-01T00:01:00Z",
                bindings=[dict(name="target", value="synthetic-host")]) | changes


def profile_data(**changes):
    return dict(profile_id="synthetic-profile", profile_version="0.1.0", scenario_id="SCN-999",
                scenario_version="0.1.0", scenario_fingerprint="a" * 64, rules=[rule_data()]) | changes
