"""Elastic is a separate source; existing Windows/Wazuh contracts stay exact."""

from hashlib import sha256

import pytest
from pydantic import ValidationError

from aegis_verify.models import CanonicalEventV2
from aegis_verify.models.scenario import ScenarioManifest
from aegis_verify.validation import ValidationEngineError
from aegis_verify.validation.contracts import AssertionRule, validate_rule_source


def _rule(source_type):
    return AssertionRule(
        assertion_id="SCN-999-A01", role="telemetry", capability="supported",
        source_type=source_type,
        scope=[dict(field="hostname", op="eq", binding="target_host"),
               dict(field="event_provider", op="eq", value="Microsoft-Windows-Sysmon")],
    )


def test_elastic_canonical_events_and_direct_scenario_assertions_are_accepted():
    event = CanonicalEventV2(
        event_id="synthetic-elastic", source_type="elastic", environment_id="example-lab",
        timestamp="2026-01-01T00:00:10Z", ingested_at="2026-01-01T00:00:11Z",
        raw_event_ref="synthetic#record=1", raw_event_hash=sha256(b"synthetic").hexdigest(),
    )
    scenario = ScenarioManifest.model_validate(dict(
        id="SCN-999", name="Synthetic Elastic boundary", version="0.1.0", status="draft",
        description="Synthetic source contract, not lab evidence.",
        safety=dict(destructive=False, authorization_required=True, notes="Approved synthetic test only."),
        expected_sources=["elastic"], expected_outcome="detected",
        assertions=[dict(id="SCN-999-A01", description="Elastic telemetry exists.", source="elastic")],
    ))
    assert event.source_type == scenario.assertions[0].source == "elastic"
    validate_rule_source(_rule("elastic"), "elastic")


@pytest.mark.parametrize("source", ["sysmon", "powershell", "wazuh", "suricata"])
def test_elastic_does_not_change_existing_manifest_source_bindings(source):
    with pytest.raises(ValidationEngineError) as caught:
        validate_rule_source(_rule("elastic"), source)
    assert caught.value.code == "assertion_binding"


@pytest.mark.parametrize("source", ["sysmon", "powershell"])
def test_existing_semantic_windows_sources_still_accept_wazuh(source):
    validate_rule_source(_rule("wazuh"), source)


@pytest.mark.parametrize("source", ["Elastic", "elasticsearch", "elastic-security"])
def test_elastic_source_name_is_closed_and_case_exact(source):
    with pytest.raises(ValidationError):
        _rule(source)
