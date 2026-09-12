"""Synthetic-only tests for the two bounded Windows telemetry profiles."""

import hashlib
import json
from pathlib import Path

import pytest

from aegis_verify.connectors import wazuh


FIXTURES = Path(__file__).resolve().parents[2] / 'tests/fixtures/wazuh/windows-telemetry'
PROFILES = [
    ('sysmon1', 'parse_wazuh_sysmon1_document', 'wazuh-sysmon1-v1'),
    ('powershell4104', 'parse_wazuh_powershell4104_document', 'wazuh-powershell4104-v1'),
]
CONTEXT = dict(source_ref='synthetic-record', environment_id='synthetic-env',
               ingested_at='2026-01-01T00:01:00Z', collection_mode='direct')


def sample(kind):
    return (FIXTURES / f'{kind}.synthetic.json').read_bytes()


def change(raw, path, value=None, *, omit=False):
    data = json.loads(raw)
    parts = path.split('.')
    parent = data
    for part in parts[:-1]:
        parent = parent[part]
    if omit:
        parent.pop(parts[-1], None)
    else:
        parent[parts[-1]] = value
    return json.dumps(data, ensure_ascii=True).encode()


def parse(kind, raw=None, **context):
    name = next(name for profile, name, _ in PROFILES if profile == kind)
    api = getattr(wazuh, name, None)
    assert callable(api), f'missing Windows telemetry parser: {name}'
    return api(sample(kind) if raw is None else raw, **(CONTEXT | context))


def test_sysmon_maps_created_process_not_provider_process():
    result = parse('sysmon1')
    event = result.event
    assert event.process_id == 4242  # not the provider's system.processID=4
    assert event.process_name == r'C:\Synthetic\powershell.exe'
    assert event.parent_process_name == r'C:\Synthetic\launcher.exe'
    assert event.command_line == r'  powershell.exe -File C:\Synthetic\example.ps1  '
    assert event.username == r'SYNTHETIC\operator'
    assert event.timestamp.isoformat() == '2026-01-01T00:00:01.123456789Z'
    assert event.file_path is None and event.file_hash is None
    assert result.provenance.process_guid == '{00000000-0000-0000-0000-000000000001}'
    assert result.provenance.parent_process_id == 4000


def test_powershell_script_is_not_a_process_command_line():
    result = parse('powershell4104')
    event = result.event
    assert event.process_id == 4242
    assert event.file_path == r'C:\Synthetic\example.ps1'
    assert event.command_line is None
    assert event.process_name is None and event.parent_process_name is None
    assert event.username is None and event.event_action is None
    assert result.provenance.script_block_id == '00000000-0000-0000-0000-000000000003'
    assert result.provenance.message_number == result.provenance.message_total == 1
    assert 'synthetic marker' not in result.model_dump_json()


@pytest.mark.parametrize('kind,api,key', PROFILES)
def test_exact_bytes_evidence_and_raw_only_unknown_fields(kind, api, key):
    raw = sample(kind)
    result = parse(kind, raw)
    event = result.event
    assert event.schema_version == '2.0' and event.source_type == 'wazuh'
    assert event.asset_id == '901' and event.hostname == 'synthetic-endpoint'
    assert event.raw_event_hash == hashlib.sha256(raw).hexdigest()
    identity = json.dumps(['wazuh-evidence-v1', 'synthetic-env', 'synthetic-record', 1,
                           hashlib.sha256(raw).hexdigest()], separators=(',', ':')).encode()
    assert event.event_id == 'wazuh:evidence-v1:' + hashlib.sha256(identity).hexdigest()
    assert event.raw_event_ref == 'synthetic-record#record=1'
    assert result.provenance.mapping_version == key
    assert result.provenance.event_id == event.event_id
    assert result.provenance.raw_event_hash == event.raw_event_hash
    assert result.provenance.windows_event_id == ('1' if kind == 'sysmon1' else '4104')
    assert result.provenance.windows_record_id == ('101' if kind == 'sysmon1' else '102')
    assert event == parse(kind, raw).event
    assert parse(kind, raw + b'\n').event.event_id != event.event_id
    extra = change(raw, '_source.vendorOnly', 'PRIVATE-MARKER')
    mapped = parse(kind, extra)
    assert 'PRIVATE-MARKER' not in mapped.model_dump_json()
    assert mapped.event.event_id != event.event_id


@pytest.mark.parametrize('kind,api,key', PROFILES)
@pytest.mark.parametrize('mode,asset', [('direct', '901'), ('forwarded', None), ('unknown', None)])
def test_origin_not_guessed_from_collector(kind, api, key, mode, asset):
    result = parse(kind, collection_mode=mode)
    assert result.event.asset_id == asset
    raw = change(sample(kind), '_source.data.win.system.computer', omit=True)
    assert parse(kind, raw, collection_mode=mode).event.hostname is None


@pytest.mark.parametrize('kind,api,key', PROFILES)
@pytest.mark.parametrize('field,value', [('providerName', 'wrong'), ('channel', 'wrong'),
                                       ('eventID', '4688'), ('eventID', 1)])
def test_rejects_wrong_source_profile(kind, api, key, field, value):
    with pytest.raises(wazuh.WazuhParseError):
        parse(kind, change(sample(kind), '_source.data.win.system.' + field, value))


@pytest.mark.parametrize('kind,api,key', PROFILES)
@pytest.mark.parametrize('value', [None, '', 123, '2026-01-01T00:00:00',
                                 '2026-01-01T00:00:00.1234567890Z'])
def test_no_fallback_to_wazuh_or_sysmon_utc_time(kind, api, key, value):
    with pytest.raises(wazuh.WazuhParseError):
        parse(kind, change(sample(kind), '_source.data.win.system.systemTime', value))


@pytest.mark.parametrize('kind,api,key', PROFILES)
@pytest.mark.parametrize('value', ['0', '0042', '4294967295', None])
def test_decimal_pid_and_absence(kind, api, key, value):
    path = '_source.data.win.' + ('eventdata.processId' if kind == 'sysmon1' else 'system.processID')
    event = parse(kind, change(sample(kind), path, value)).event
    assert event.process_id == (None if value is None else int(value))


@pytest.mark.parametrize('kind,api,key', PROFILES)
@pytest.mark.parametrize('value', [True, 42, 1.5, '-1', '0x42', '+1', ' 1', '１', '', '1' * 129])
def test_rejects_non_decimal_string_pid(kind, api, key, value):
    path = '_source.data.win.' + ('eventdata.processId' if kind == 'sysmon1' else 'system.processID')
    with pytest.raises(wazuh.WazuhParseError):
        parse(kind, change(sample(kind), path, value))


@pytest.mark.parametrize('field,value', [('messageNumber', '2'), ('messageTotal', '2'),
    ('messageTotal', None), ('messageNumber', None), ('messageTotal', '0'),
    ('messageTotal', True), ('messageTotal', 1), ('messageTotal', '01'),
    ('scriptBlockText', None), ('scriptBlockText', ''), ('scriptBlockText', '  '),
    ('scriptBlockText', 123)])
def test_powershell_requires_explicit_complete_single_part(field, value):
    with pytest.raises(wazuh.WazuhParseError):
        parse('powershell4104', change(sample('powershell4104'), '_source.data.win.eventdata.' + field, value))


@pytest.mark.parametrize('kind,api,key', PROFILES)
def test_legacy_4688_does_not_silently_accept_new_profiles(kind, api, key):
    with pytest.raises(wazuh.WazuhParseError) as caught:
        wazuh.parse_wazuh_document(sample(kind), **CONTEXT)
    assert caught.value.diagnostic.code == 'unsupported_profile'


@pytest.mark.parametrize('kind,api,key', PROFILES)
@pytest.mark.parametrize('raw', [b'[]', b'{"x":1,"x":2}', b'{"secret":NaN}', b'\xff',
    b'{"x":"\\ud800"}', b'{' + b' ' * (256 * 1024) + b'}'],
    ids=['array', 'duplicate', 'nan', 'encoding', 'unicode', 'oversize'])
def test_bounded_json_boundary_and_safe_errors(kind, api, key, raw):
    with pytest.raises(wazuh.WazuhParseError) as caught:
        parse(kind, raw)
    assert 'secret' not in str(caught.value)


@pytest.mark.parametrize('kind,api,key', PROFILES)
def test_bad_optional_fields_do_not_leak_source_values(kind, api, key):
    raw = change(sample(kind), '_source.rule.level', 'PRIVATE-MARKER')
    with pytest.raises(wazuh.WazuhParseError) as caught:
        parse(kind, raw)
    assert 'PRIVATE-MARKER' not in str(caught.value)


@pytest.mark.parametrize('kind,api,key', PROFILES)
@pytest.mark.parametrize('field,value', [('source_ref', '../escape'), ('source_ref', ''),
    ('environment_id', ' '), ('environment_id', '\ud800'), ('collection_mode', 'guessed'),
    ('ingested_at', '2026-01-01T00:00:00')])
def test_new_parsers_enforce_existing_context_boundary(kind, api, key, field, value):
    with pytest.raises(wazuh.WazuhParseError) as caught:
        parse(kind, **{field: value})
    assert caught.value.diagnostic.code == 'invalid_context'


@pytest.mark.parametrize('kind,api,key', PROFILES)
@pytest.mark.parametrize('digits', ['', '.1', '.123456', '.1234567', '.123456789'])
def test_offset_conversion_is_lossless(kind, api, key, digits):
    raw = change(sample(kind), '_source.data.win.system.systemTime',
                 f'2026-01-01T00:00:00{digits}+07:00')
    result = parse(kind, raw)
    assert result.event.timestamp.isoformat() == f'2025-12-31T17:00:00{digits}Z'
    assert result.provenance.source_fraction_digits == max(0, len(digits) - 1)


@pytest.mark.parametrize('kind,api,key', PROFILES)
def test_absent_optional_context_stays_null_and_does_not_change_identity(kind, api, key):
    raw = sample(kind)
    for path in ['_source.id', '_source.agent', '_source.manager', '_source.rule',
                 '_source.data.win.system.computer', '_source.data.win.system.eventRecordID']:
        raw = change(raw, path, omit=True)
    event = parse(kind, raw).event
    for field in ['source_record_id', 'asset_id', 'hostname', 'rule_id', 'severity',
                  'src_ip', 'dst_ip', 'src_port', 'dst_port', 'event_action', 'technique_ids']:
        assert getattr(event, field) is None
    base = parse(kind).event
    assert parse(kind, collection_mode='forwarded').event.event_id == base.event_id
    assert parse(kind, source_ref='different-record').event.event_id != base.event_id
    assert parse(kind, environment_id='different-env').event.event_id != base.event_id
    assert parse(kind, ingested_at='2027-01-01T00:00:00Z').event.event_id == base.event_id


@pytest.mark.parametrize('kind,api,key', PROFILES)
@pytest.mark.parametrize('path', ['_source.data', '_source.data.win', '_source.data.win.system',
    '_source.agent', '_source.manager', '_source.rule', '_source.data.win.eventdata'])
def test_wrong_object_shape_is_rejected(kind, api, key, path):
    with pytest.raises(wazuh.WazuhParseError):
        parse(kind, change(sample(kind), path, []))


@pytest.mark.parametrize('kind,field', [('sysmon1', 'image'), ('sysmon1', 'commandLine'),
    ('sysmon1', 'parentImage'), ('sysmon1', 'user'), ('sysmon1', 'processGuid'),
    ('sysmon1', 'parentProcessGuid'), ('powershell4104', 'path'), ('powershell4104', 'scriptBlockId')])
@pytest.mark.parametrize('value', [None, 7])
def test_optional_mapped_text_is_null_or_text_only(kind, field, value):
    raw = change(sample(kind), '_source.data.win.eventdata.' + field, value)
    if value is None:
        parse(kind, raw)
    else:
        with pytest.raises(wazuh.WazuhParseError):
            parse(kind, raw)


def test_sysmon_without_eventdata_does_not_infer_process_from_provider():
    raw = change(sample('sysmon1'), '_source.data.win.eventdata', omit=True)
    event = parse('sysmon1', raw).event
    assert event.process_id is None and event.process_name is None


@pytest.mark.parametrize('field', ['messageNumber', 'messageTotal', 'scriptBlockText'])
def test_missing_powershell_part_metadata_is_explicit_error(field):
    raw = change(sample('powershell4104'), '_source.data.win.eventdata.' + field, omit=True)
    with pytest.raises(wazuh.WazuhParseError) as caught:
        parse('powershell4104', raw)
    assert caught.value.diagnostic.code == 'incomplete_script'
    assert caught.value.diagnostic.field_path == '_source.data.win.eventdata.' + field


def test_fragmentation_error_has_no_script_content():
    raw = change(sample('powershell4104'), '_source.data.win.eventdata.messageTotal', '3')
    with pytest.raises(wazuh.WazuhParseError) as caught:
        parse('powershell4104', raw)
    assert caught.value.diagnostic.code == 'unsupported_fragmentation'
    assert 'synthetic marker' not in str(caught.value)
