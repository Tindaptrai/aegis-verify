"""Synthetic manifest inputs test the contract, not security detection outcomes."""

import json

import pytest
from pydantic import ValidationError

from aegis_verify.models import ScenarioManifest


@pytest.fixture
def scenario_data():
    return {
        "id": "SCN-900", "name": "Unit scenario", "version": "0.1.0",
        "status": "draft", "description": "Unit evidence expectation.",
        "safety": {"destructive": False, "authorization_required": True,
                   "notes": "Unit data only; do not execute."},
        "expected_sources": ["wazuh"], "expected_outcome": "detected",
        "assertions": [{"id": "SCN-900-A01", "source": "wazuh",
                        "description": "Unit alert evidence exists."}],
    }


def test_minimal_contract_round_trip_does_not_invent_expectations(scenario_data):
    manifest = ScenarioManifest.model_validate(scenario_data)
    assert json.loads(manifest.model_dump_json()) == scenario_data | {"tags": None}
    assert ScenarioManifest.model_validate_json(manifest.model_dump_json()) == manifest


@pytest.mark.parametrize("field", [
    "id", "name", "version", "status", "description", "safety",
    "expected_sources", "expected_outcome", "assertions",
])
def test_required_manifest_fields_report_their_location(scenario_data, field):
    del scenario_data[field]
    with pytest.raises(ValidationError) as error:
        ScenarioManifest.model_validate(scenario_data)
    assert (field,) in [issue["loc"] for issue in error.value.errors()]


@pytest.mark.parametrize("field,value", [
    ("id", "SCN-9"), ("id", "SCN-900\n"), ("id", "SCN-９００"),
    ("id", " SCN-900"), ("id", None), ("id", 900),
    ("name", ""), ("name", " \n"), ("name", 5), ("name", b"name"),
    ("description", ""), ("description", None),
    ("version", "01.2.3"), ("version", "1.2"), ("version", 1.0),
    ("version", "1.2.3-alpha"), ("version", "1.2.3+build"),
    ("version", "1.2.3\n"), ("version", "１.2.3"),
    ("status", "approved"), ("status", b"draft"), ("status", None),
    ("expected_outcome", "pass"), ("expected_outcome", "missing_telemetry"),
    ("expected_outcome", b"detected"), ("expected_outcome", None),
    ("expected_sources", []), ("expected_sources", None),
    ("expected_sources", "wazuh"), ("expected_sources", {"wazuh"}),
    ("expected_sources", ["Wazuh"]), ("expected_sources", ["other"]),
    ("expected_sources", [b"wazuh"]), ("expected_sources", [True]),
    ("expected_sources", ["wazuh", "wazuh"]),
    ("assertions", []), ("assertions", None), ("assertions", {}),
    ("tags", "unit"), ("tags", {"unit"}), ("tags", [1]), ("tags", [" "]),
    ("unrecognized", "unit"),
])
def test_invalid_field_values_are_not_coerced_or_repaired(scenario_data, field, value):
    scenario_data[field] = value
    with pytest.raises(ValidationError) as error:
        ScenarioManifest.model_validate(scenario_data)
    assert field in [issue["loc"][0] for issue in error.value.errors()]


@pytest.mark.parametrize("field", ["destructive", "authorization_required", "notes"])
def test_missing_safety_field_is_localized(scenario_data, field):
    del scenario_data["safety"][field]
    with pytest.raises(ValidationError) as error:
        ScenarioManifest.model_validate(scenario_data)
    assert ("safety", field) in [issue["loc"] for issue in error.value.errors()]


@pytest.mark.parametrize("field,values", [
    ("destructive", [True, 0, 1, "false", None]),
    ("authorization_required", [False, 0, 1, "true", None]),
    ("notes", ["", " \n", None, 1]),
    ("unexpected", ["unit"]),
])
def test_safety_rejects_wrong_values_and_coercion(scenario_data, field, values):
    for value in values:
        with pytest.raises(ValidationError) as error:
            ScenarioManifest.model_validate(scenario_data | {
                "safety": scenario_data["safety"] | {field: value},
            })
        assert ("safety", field) in [issue["loc"] for issue in error.value.errors()]


@pytest.mark.parametrize("field", ["id", "description", "source"])
def test_assertion_requires_id_description_and_source(scenario_data, field):
    del scenario_data["assertions"][0][field]
    with pytest.raises(ValidationError) as error:
        ScenarioManifest.model_validate(scenario_data)
    assert ("assertions", 0, field) in [issue["loc"] for issue in error.value.errors()]


@pytest.mark.parametrize("field,value", [
    ("id", "SCN-900-A1"), ("id", "SCN-900-A01\n"), ("id", "SCN-901-A01"),
    ("description", ""), ("description", " \t"), ("description", None),
    ("source", "suricata"), ("source", b"wazuh"), ("source", "invented"),
    ("unexpected", "unit"),
])
def test_invalid_assertions_report_index_and_field(scenario_data, field, value):
    scenario_data["assertions"][0][field] = value
    with pytest.raises(ValidationError) as error:
        ScenarioManifest.model_validate(scenario_data)
    assert ("assertions", 0, field) in [issue["loc"] for issue in error.value.errors()]


def test_duplicate_assertion_ids_are_rejected_at_second_id(scenario_data):
    scenario_data["assertions"].append(dict(scenario_data["assertions"][0]))
    with pytest.raises(ValidationError) as error:
        ScenarioManifest.model_validate(scenario_data)
    assert ("assertions", 1, "id") in [issue["loc"] for issue in error.value.errors()]


def test_every_declared_source_needs_an_assertion(scenario_data):
    scenario_data["expected_sources"].append("suricata")
    with pytest.raises(ValidationError) as error:
        ScenarioManifest.model_validate(scenario_data)
    assert ("expected_sources", 1) in [issue["loc"] for issue in error.value.errors()]


@pytest.mark.parametrize("source", ["sysmon", "powershell", "wazuh", "suricata", "pfsense", "cowrie", "snort"])
@pytest.mark.parametrize("outcome", ["detected", "prevented"])
def test_logical_sources_and_outcomes_preserve_the_authored_values(scenario_data, source, outcome):
    scenario_data["expected_sources"] = [source]
    scenario_data["assertions"][0]["source"] = source
    scenario_data["expected_outcome"] = outcome
    manifest = ScenarioManifest.model_validate(scenario_data)
    assert manifest.model_dump(mode="json") == scenario_data | {"tags": None}


@pytest.mark.parametrize("tags", [None, [], ["second", "first"], ["same", "same"]])
def test_tags_preserve_absence_emptiness_order_and_authored_duplicates(scenario_data, tags):
    manifest = ScenarioManifest.model_validate(scenario_data | {"tags": tags})
    assert manifest.model_dump(mode="json")["tags"] == tags


@pytest.mark.parametrize("text", ["  Tiếng Việt 🚀  ", "a\u0301\t\n"])
def test_text_is_not_normalized(scenario_data, text):
    scenario_data["name"] = text
    scenario_data["description"] = text
    scenario_data["safety"]["notes"] = text
    scenario_data["assertions"][0]["description"] = text
    scenario_data["tags"] = [text]
    manifest = ScenarioManifest.model_validate(scenario_data)
    assert json.loads(manifest.model_dump_json()) == scenario_data


@pytest.mark.parametrize("path", [
    ("name",), ("description",), ("safety", "notes"),
    ("assertions", 0, "description"), ("tags", 0),
])
@pytest.mark.parametrize("surrogate", ["\ud800", "\udfff"])
def test_malformed_unicode_cannot_enter_a_serializable_manifest(scenario_data, path, surrogate):
    scenario_data["tags"] = ["unit"]
    target = scenario_data
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = "PRIVATE_UNIT_MARKER" + surrogate
    with pytest.raises(ValidationError) as error:
        ScenarioManifest.model_validate(scenario_data)
    assert path in [issue["loc"] for issue in error.value.errors()]
    assert "PRIVATE_UNIT_MARKER" not in str(error.value)


def test_nested_collections_and_models_are_immutable_and_detached(scenario_data):
    scenario_data["tags"] = ["unit"]
    manifest = ScenarioManifest.model_validate(scenario_data)
    scenario_data["safety"]["notes"] = "changed"
    scenario_data["assertions"][0]["description"] = "changed"
    scenario_data["expected_sources"].append("cowrie")
    scenario_data["tags"].append("changed")
    assert manifest.safety.notes == "Unit data only; do not execute."
    assert manifest.assertions[0].description == "Unit alert evidence exists."
    assert manifest.expected_sources == ("wazuh",)
    assert manifest.tags == ("unit",)
    with pytest.raises(ValidationError):
        manifest.expected_outcome = "prevented"
    with pytest.raises(ValidationError):
        manifest.safety.destructive = True
    with pytest.raises(ValidationError):
        manifest.assertions[0].source = "cowrie"
    with pytest.raises(TypeError):
        manifest.assertions[0] = manifest.assertions[0]
    with pytest.raises(TypeError):
        manifest.tags[0] = "changed"


def test_schema_exposes_required_contract_and_forbids_unknown_fields():
    schema = ScenarioManifest.model_json_schema()
    assert schema["additionalProperties"] is False
    assert {"id", "safety", "assertions", "expected_outcome"} <= set(schema["required"])
    assert schema["$defs"]["ScenarioAssertion"]["additionalProperties"] is False
    assert schema["$defs"]["ScenarioSafety"]["additionalProperties"] is False
