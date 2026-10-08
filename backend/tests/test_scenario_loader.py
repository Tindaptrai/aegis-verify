"""Offline YAML boundary tests; no live payloads or incident evidence."""

import json
from pathlib import Path
import traceback

import pytest
import yaml

from aegis_verify.models import ScenarioManifest
from aegis_verify.scenario_loader import ScenarioLoadError, load_scenario, parse_scenario_yaml


MINIMAL = """id: SCN-900
name: Unit scenario
version: 0.1.0
status: draft
description: Unit evidence expectation.
safety:
  destructive: false
  authorization_required: true
  notes: Unit data only; do not execute.
expected_sources: [wazuh]
expected_outcome: detected
assertions:
  - id: SCN-900-A01
    source: wazuh
    description: Unit alert evidence exists.
"""
REPO = Path(__file__).resolve().parents[2]


def parse(text):
    return parse_scenario_yaml(text, source_name="unit.yaml")


def test_yaml_reader_preserves_authored_contract():
    result = parse(MINIMAL)
    assert result.id == "SCN-900"
    assert result.assertions[0].description == "Unit alert evidence exists."
    assert result.tags is None
    assert result.expected_outcome == "detected"
    assert ScenarioManifest.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("filename,scenario_id,version,outcome,sources,assertion_sources", [
    ("SCN-001-powershell-execution.yaml", "SCN-001", "0.1.0", "detected",
     ["sysmon", "powershell", "wazuh"], ["sysmon", "powershell", "wazuh"]),
    ("SCN-002-attempted-exfiltration.yaml", "SCN-002", "0.1.0", "prevented",
     ["wazuh", "suricata", "pfsense"], ["wazuh", "suricata", "pfsense", "wazuh"]),
    ("SCN-003-internal-deception.yaml", "SCN-003", "0.1.0", "detected",
     ["suricata", "pfsense", "cowrie", "wazuh"], ["suricata", "pfsense", "cowrie", "wazuh"]),
    # SCN-004 went to 0.2.0 when the SIEM alert became assertion A04 (a second wazuh source).
    ("SCN-004-attempted-exfiltration-lab-c.yaml", "SCN-004", "0.2.0", "prevented",
     ["wazuh", "snort", "opnsense"], ["wazuh", "snort", "opnsense", "wazuh"]),
])
def test_committed_manifests_load_without_writes(filename, scenario_id, version, outcome, sources, assertion_sources):
    path = REPO / "scenarios" / filename
    before = path.read_bytes()
    manifest = load_scenario(path)
    assert manifest.id == scenario_id
    assert manifest.version == version
    assert manifest.status == "draft"
    assert manifest.expected_outcome == outcome
    assert list(manifest.expected_sources) == sources
    assert [item.source for item in manifest.assertions] == assertion_sources
    assert [item.id for item in manifest.assertions] == [
        scenario_id + f"-A{index:02d}" for index in range(1, len(assertion_sources) + 1)
    ]
    # The independent standard loader checks text/order preservation on reviewed,
    # trusted manifests only. Literal outcomes/sources above are the ground truth.
    assert manifest.model_dump(mode="json") == yaml.safe_load(before)
    assert path.read_bytes() == before


@pytest.mark.parametrize("text,code", [
    ("", "yaml_root"), ("# empty\n", "yaml_root"), ("null", "yaml_root"),
    ("[]", "yaml_root"), ("42", "yaml_root"),
    (MINIMAL + "---\n{}\n", "yaml_documents"),
    (MINIMAL + "name: replaced\n", "yaml_duplicate_key"),
    (MINIMAL.replace("  destructive: false", "  destructive: false\n  destructive: true"), "yaml_duplicate_key"),
    (MINIMAL.replace("    source: wazuh", "    source: wazuh\n    source: cowrie"), "yaml_duplicate_key"),
    (MINIMAL + '"name": replaced\n', "yaml_duplicate_key"),
    (MINIMAL + "1: value\n", "yaml_key"),
    (MINIMAL + "[a, b]: value\n", "yaml_key"),
    (MINIMAL + "true: value\n", "yaml_key"),
    (MINIMAL + "<<: {name: replaced}\n", "yaml_merge"),
    (MINIMAL + '"<<": {name: replaced}\n', "yaml_merge"),
    (MINIMAL.replace("name: Unit scenario", "name: &name Unit scenario"), "yaml_alias"),
    (MINIMAL.replace("name: Unit scenario", "name: *undefined"), "yaml_alias"),
    ("&self [*self]", "yaml_alias"),
    (MINIMAL + "extra: !custom value\n", "yaml_tag"),
    (MINIMAL + "extra: !!python/object/apply:builtins.str [unit]\n", "yaml_tag"),
    (MINIMAL + "extra: !!binary dW5pdA==\n", "yaml_tag"),
    (MINIMAL + "extra: !!timestamp 2026-09-06\n", "yaml_tag"),
    (MINIMAL + "extra: 2026-09-06\n", "yaml_tag"),
    (MINIMAL + "extra: !!set {unit: null}\n", "yaml_tag"),
    (MINIMAL + "extra: [unfinished", "yaml_syntax"),
    (MINIMAL + "extra: \x00", "yaml_syntax"),
])
def test_yaml_policy_rejects_input_instead_of_repairing_it(text, code):
    with pytest.raises(ScenarioLoadError) as error:
        parse(text)
    assert error.value.source_name == "unit.yaml"
    assert error.value.diagnostics[0].code == code


@pytest.mark.parametrize("value", ["yes", "no", "on", "off", "True", "FALSE", "0", "1", '"false"', "null"])
def test_only_literal_lowercase_booleans_are_safety_flags(value):
    with pytest.raises(ScenarioLoadError) as error:
        parse(MINIMAL.replace("destructive: false", "destructive: " + value))
    assert error.value.scenario_id == "SCN-900"
    assert error.value.diagnostics[0].field == ("safety", "destructive")


@pytest.mark.parametrize("value", ["!!bool yes", "!!bool FALSE", "!!int bad", "!!float bad", "!!null bad"])
def test_explicit_scalar_tags_cannot_bypass_scalar_rules(value):
    with pytest.raises(ScenarioLoadError):
        parse(MINIMAL.replace("destructive: false", "destructive: " + value))


def test_reader_does_not_change_global_yaml_boolean_resolution():
    assert yaml.safe_load("flag: yes") == {"flag": True}
    assert parse(MINIMAL.replace("name: Unit scenario", "name: yes")).name == "yes"
    assert yaml.safe_load("flag: yes") == {"flag": True}


def test_model_errors_name_scenario_and_field_without_echoing_values():
    text = MINIMAL.replace("expected_outcome: detected", "expected_outcome: PRIVATE_UNIT_MARKER")
    with pytest.raises(ScenarioLoadError) as error:
        parse(text)
    assert error.value.scenario_id == "SCN-900"
    assert error.value.diagnostics[0].field == ("expected_outcome",)
    assert "SCN-900" in str(error.value)
    assert "expected_outcome" in str(error.value)
    assert "PRIVATE_UNIT_MARKER" not in str(error.value)
    assert "PRIVATE_UNIT_MARKER" not in "".join(traceback.format_exception(error.value))


@pytest.mark.parametrize("extra", [
    "PRIVATE_UNIT_MARKER: value\n",
    "extra: {PRIVATE_UNIT_MARKER: value}\n",
    "extra: [PRIVATE_UNIT_MARKER\n",
    "PRIVATE_UNIT_MARKER: one\nPRIVATE_UNIT_MARKER: two\n",
])
def test_unknown_keys_and_parser_snippets_are_not_in_public_diagnostics(extra):
    with pytest.raises(ScenarioLoadError) as error:
        parse(MINIMAL + extra)
    assert "PRIVATE_UNIT_MARKER" not in str(error.value)
    assert "PRIVATE_UNIT_MARKER" not in repr(error.value.diagnostics)
    assert "PRIVATE_UNIT_MARKER" not in "".join(traceback.format_exception(error.value))


def test_duplicate_key_error_has_one_based_source_position():
    with pytest.raises(ScenarioLoadError) as error:
        parse(MINIMAL + "name: replacement\n")
    diagnostic = error.value.diagnostics[0]
    assert diagnostic.line == 16
    assert diagnostic.column == 1


@pytest.mark.parametrize("text", [MINIMAL.replace("id: SCN-900\n", "", 1),
                                       MINIMAL.replace("id: SCN-900\n", "id: PRIVATE_UNIT_MARKER\n", 1)])
def test_missing_or_invalid_id_uses_source_label(text):
    with pytest.raises(ScenarioLoadError) as error:
        parse(text)
    assert error.value.scenario_id is None
    assert "unit.yaml" in str(error.value)
    assert error.value.diagnostics[0].field == ("id",)
    assert "PRIVATE_UNIT_MARKER" not in str(error.value)


@pytest.mark.parametrize("text", [MINIMAL + "# \ud800", MINIMAL.replace("name: Unit scenario", 'name: "\\uD800"')])
def test_raw_and_escaped_surrogates_are_rejected(text):
    with pytest.raises(ScenarioLoadError):
        parse(text)


@pytest.mark.parametrize("prefix", ["", "\ufeff"])
def test_exact_byte_limit_accepts_boundary_and_rejects_next_byte(prefix):
    text = prefix + MINIMAL + "# "
    text += "x" * (256 * 1024 - len(text.encode("utf-8")))
    assert parse(text).id == "SCN-900"
    with pytest.raises(ScenarioLoadError) as error:
        parse(text + "x")
    assert error.value.diagnostics[0].code == "input_size"


def test_byte_limit_counts_multibyte_text_not_characters():
    text = MINIMAL + "# " + "ế" * (100 * 1024)
    assert len(text) < 256 * 1024
    with pytest.raises(ScenarioLoadError) as error:
        parse(text)
    assert error.value.diagnostics[0].code == "input_size"


@pytest.mark.parametrize("levels,code", [(19, "extra_forbidden"), (20, "yaml_depth"), (2000, "yaml_depth")])
def test_nesting_budget_is_checked_before_recursive_construction(levels, code):
    # The document mapping is depth 1; 19 nested sequences reach depth 20.
    text = MINIMAL + "extra: " + "[" * levels + "x" + "]" * levels
    with pytest.raises(ScenarioLoadError) as error:
        parse(text)
    assert error.value.diagnostics[0].code == code


@pytest.mark.parametrize("items,code", [(9997, "missing"), (9998, "yaml_nodes")])
def test_node_budget_counts_mapping_sequence_keys_and_scalars(items, code):
    # Root mapping + key scalar + sequence + items = items + 3 nodes.
    text = "extra: [" + ",".join(["x"] * items) + "]"
    with pytest.raises(ScenarioLoadError) as error:
        parse(text)
    assert error.value.diagnostics[0].code == code


@pytest.mark.parametrize("with_bom", [False, True])
def test_utf8_file_is_read_without_rewriting_it(tmp_path, with_bom):
    path = tmp_path / "scenario.yaml"
    content = MINIMAL.replace("name: Unit scenario", "name: Tiếng Việt 🚀").encode("utf-8")
    if with_bom:
        content = b"\xef\xbb\xbf" + content
    path.write_bytes(content)
    assert load_scenario(str(path)).name == "Tiếng Việt 🚀"
    assert path.read_bytes() == content


@pytest.mark.parametrize("content,code", [(b"\xff", "input_encoding"), (b"x" * (256 * 1024 + 1), "input_size")],
                         ids=["invalid-utf8", "oversized"])
def test_file_rejects_encoding_or_size_before_yaml_parsing(tmp_path, content, code):
    path = tmp_path / "scenario.yaml"
    path.write_bytes(content)
    with pytest.raises(ScenarioLoadError) as error:
        load_scenario(path)
    assert error.value.diagnostics[0].code == code
    assert path.read_bytes() == content


def test_missing_file_has_path_context(tmp_path):
    path = tmp_path / "absent.yaml"
    with pytest.raises(ScenarioLoadError) as error:
        load_scenario(path)
    assert error.value.source_name == str(path)
    assert error.value.diagnostics[0].code == "input_io"
    assert not path.exists()


def test_reader_does_not_interpolate_environment_variables(monkeypatch):
    monkeypatch.setenv("AEGIS_UNIT_SENTINEL", "PRIVATE_UNIT_MARKER")
    result = parse(MINIMAL.replace("name: Unit scenario", "name: ${AEGIS_UNIT_SENTINEL}"))
    assert result.name == "${AEGIS_UNIT_SENTINEL}"


def test_json_is_accepted_as_yaml_without_changing_contract():
    # YAML's JSON syntax still goes through duplicate-key/policy checks.
    data = yaml.safe_load(MINIMAL)
    assert parse(json.dumps(data)).model_dump(mode="json") == data | {"tags": None}


@pytest.mark.parametrize("value", ["!!int ''", "!!float ''", "!!int '-'", "!!float '+'"])
def test_malformed_numeric_tags_produce_controlled_errors(value):
    with pytest.raises(ScenarioLoadError) as error:
        parse(MINIMAL.replace("name: Unit scenario", "name: " + value))
    assert error.value.diagnostics[0].code == "yaml_scalar"


def test_scalar_tag_cannot_silently_discard_mapping_members():
    # SafeConstructor supports a legacy scalar shorthand using '=' inside a map.
    # A manifest must not turn that map into text while dropping its other keys.
    text = MINIMAL.replace("name: Unit scenario", "name: !!str {=: Unit scenario, ignored: value}")
    with pytest.raises(ScenarioLoadError) as error:
        parse(text)
    assert error.value.diagnostics[0].code == "yaml_tag_shape"


@pytest.mark.parametrize("value", ["!!map unit", "!!seq unit", "!!str [unit]", "!!int [1]"])
def test_standard_tag_must_match_the_yaml_node_shape(value):
    with pytest.raises(ScenarioLoadError) as error:
        parse(MINIMAL.replace("name: Unit scenario", "name: " + value))
    assert error.value.diagnostics[0].code == "yaml_tag_shape"
