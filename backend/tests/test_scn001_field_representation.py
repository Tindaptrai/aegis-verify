"""Pin how EventChannel field values reach canonical events.

Hand-authored fixtures, deliberately not produced by scripts/prepare_scn001_kit.py:
the kit builds both the data and the expectation, so a kit-generated fixture cannot
detect a wrong representation. Nothing here is lab evidence.

The open question these tests fence off is recorded in
tests/fixtures/demo/scn-001/field-representation/README.md: the declared field
profile says field values carry doubled backslashes, but that was observed on the
4104 `path` field only. `image` and `commandLine` are mapped from the same
eventdata object. On 2026-09-17 this was measured against real Wazuh 4.14.4
telemetry: all four of image, parentImage, commandLine and path carry the
JSON-escaped form of the native value. The study was corrected accordingly and
`Target` now enforces the wire representation.

These tests keep the two layers distinguishable so neither direction can drift:
a parser that normalised the escaping away, or a study that reverted to native
values, both fail here.
"""

import json
from pathlib import Path

import pytest

from test_scn001_study_run import inputs  # noqa: F401 - shared synthetic study fixture

from aegis_verify.connectors.wazuh import parse_wazuh_sysmon1_document
from aegis_verify.demo._study_contracts import is_wire_text, wire_text

FIXTURES = Path(__file__).resolve().parents[2] / 'tests/fixtures/demo/scn-001/field-representation'
SINGLE = FIXTURES / 'sysmon1-single-backslash.synthetic.json'
DOUBLED = FIXTURES / 'sysmon1-doubled-backslash.synthetic.json'

# Two consecutive backslashes in the DECODED value, i.e. the doubled convention.
DOUBLE = '\\\\'

# Written out literally so the parser assertions do not import their expectation
# from the code under test.
STUDY_EXECUTABLE = 'C:\\Synthetic\\powershell.exe'
STUDY_COMMAND = 'synthetic-powershell -File "C:\\Synthetic\\AEGIS\\lab_update.ps1"'


def parse(path):
    return parse_wazuh_sysmon1_document(
        path.read_bytes(), source_ref='synthetic-representation',
        environment_id='synthetic-env', ingested_at='2026-01-01T00:03:00Z',
        collection_mode='direct')


def test_raw_json_escaping_is_not_the_field_value():
    """Two distinct layers: bytes on disk, and the value after JSON decoding."""
    single_raw, doubled_raw = SINGLE.read_bytes(), DOUBLED.read_bytes()
    assert b'"image": "C:\\\\Synthetic\\\\powershell.exe"' in single_raw
    assert b'"image": "C:\\\\\\\\Synthetic\\\\\\\\powershell.exe"' in doubled_raw

    single_value = json.loads(single_raw)['_source']['data']['win']['eventdata']['image']
    doubled_value = json.loads(doubled_raw)['_source']['data']['win']['eventdata']['image']
    assert single_value == 'C:\\Synthetic\\powershell.exe'
    assert doubled_value == 'C:\\\\Synthetic\\\\powershell.exe'
    assert single_value != doubled_value


def test_parser_preserves_the_decoded_value_without_normalising():
    """The connector must not add or strip backslashes in either direction."""
    single, doubled = parse(SINGLE).event, parse(DOUBLED).event
    assert single.process_name == 'C:\\Synthetic\\powershell.exe'
    assert doubled.process_name == 'C:\\\\Synthetic\\\\powershell.exe'
    assert single.command_line != doubled.command_line
    assert single.parent_process_name == 'C:\\Synthetic\\launcher.exe'
    assert doubled.parent_process_name == 'C:\\\\Synthetic\\\\launcher.exe'


def test_single_backslash_values_survive_parsing_unchanged():
    """Literal expectations, independent of any study, for the single convention."""
    event = parse(SINGLE).event
    assert event.process_name == STUDY_EXECUTABLE
    assert event.command_line == STUDY_COMMAND


def test_reference_study_uses_one_wire_convention_for_every_field(inputs):
    """Every canonical value must be the wire form, measured against real telemetry.

    Wazuh 4.14.4 delivers the JSON-escaped form of the native value in every
    decoded eventdata string (image, parentImage, commandLine, path). Before
    2026-09-17 the study doubled only file_path and left process_name and
    command_line native, which would have made SCN-001-A01 miss on the first
    real run. Each value is checked against `wire_text` of its native form, not
    by counting backslashes: an escaped quote carries a single backslash.
    """
    rules = {rule['assertion_id']: rule for rule in json.loads(inputs['profile'])['rules']}
    executable = rules['SCN-001-A01']['match'][0]['value']
    commands = rules['SCN-001-A01']['match'][1]['values']
    paths = rules['SCN-001-A02']['match'][0]['values']

    for value in (executable, *commands, *paths):
        assert is_wire_text(value), value
    assert executable == wire_text('C:\\Synthetic\\powershell.exe')
    assert all(DOUBLE in value for value in (executable, *commands, *paths)), (
        'real telemetry doubles backslashes in all four eventdata fields')
    assert all(value.count('\\"') == 2 for value in commands), (
        'a real command line carries escaped quotes, not raw ones')



def test_doubled_telemetry_is_what_the_corrected_study_matches(inputs):
    """The wire fixture models real telemetry; the study must match it, and does.

    command_line is asserted explicitly, not just process_name. An executable
    path has no quotes, so doubling and escaping look identical there; the
    command line is the only field where they differ, and it is the field that
    made the escape round-trip necessary in the first place. Checking only
    process_name would leave the rule unvalidated against telemetry-shaped data.
    """
    event = parse(DOUBLED).event
    rules = {rule['assertion_id']: rule for rule in json.loads(inputs['profile'])['rules']}
    assert event.process_name == rules['SCN-001-A01']['match'][0]['value']
    assert event.command_line in rules['SCN-001-A01']['match'][1]['values']
    assert is_wire_text(event.process_name) and is_wire_text(event.command_line)
    assert is_wire_text(event.parent_process_name)
    assert '\\"' in event.command_line, 'a real command line carries escaped quotes'


def test_native_telemetry_would_no_longer_match_the_study(inputs):
    """The mirror case: single-backslash values are the native layer, not the wire one.

    Kept so the two layers stay distinguishable. A parser that normalised the
    doubling away would make this pass against the study and silently reintroduce
    the defect from the other direction.
    """
    event = parse(SINGLE).event
    rules = {rule['assertion_id']: rule for rule in json.loads(inputs['profile'])['rules']}
    assert event.process_name == STUDY_EXECUTABLE
    assert event.process_name != rules['SCN-001-A01']['match'][0]['value']


@pytest.mark.parametrize('path', [SINGLE, DOUBLED])
def test_fields_sharing_one_eventdata_object_are_pinned_together(path):
    """image, parentImage and commandLine must be asserted as a set, never inferred."""
    event = parse(path).event
    values = (event.process_name, event.parent_process_name, event.command_line)
    assert all(value is not None for value in values)
    doubled = [value.count('\\\\') > 0 for value in values]
    assert len(set(doubled)) == 1, 'one eventdata object must not mix conventions'
