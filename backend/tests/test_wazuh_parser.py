"""Reviewed sample plus explicitly artificial in-memory malformed variants."""

import hashlib
import json
from pathlib import Path

import pytest

from aegis_verify.models import CanonicalEventV2

FIXTURE = Path(__file__).resolve().parents[2] / 'tests/fixtures/wazuh/win4688.sanitized.json'
SAMPLE_HASH = '27813eae73a3276ab9bc61aeccf8572d0ba5309692ae4a888f7b8f7e55527571'
SAMPLE_ID = 'wazuh:evidence-v1:bf8783941ab703cf872f4fe04e9771a1e7b44c4ec00af62718fe8a5961a3f94a'


@pytest.fixture
def sample():
    return FIXTURE.read_bytes()


@pytest.fixture
def context():
    return dict(source_ref='win4688.sanitized.json', environment_id='unit-lab',
                ingested_at='2026-09-08T14:00:00Z', collection_mode='direct')


def test_preserves_windows_time_and_new_process(sample, context):
    from aegis_verify.connectors.wazuh import parse_wazuh_document
    result = parse_wazuh_document(sample, **context)
    assert type(result.event) is CanonicalEventV2
    assert result.event.timestamp.isoformat() == '2026-09-08T13:31:34.6479839Z'
    assert result.event.process_id == 7892
    assert result.event.src_ip is None


@pytest.fixture
def api():
    from aegis_verify.connectors import wazuh
    return wazuh


def variant(sample, path, value=None, *, omit=False):
    """Change only in-memory test data; never overwrite source fixture."""
    data = json.loads(sample)
    parts = path.split('.')
    parent = data
    for part in parts[:-1]:
        parent = parent[part]
    if omit:
        del parent[parts[-1]]
    else:
        parent[parts[-1]] = value
    return json.dumps(data, ensure_ascii=True).encode()


def test_sample_mapping_and_provenance(api, sample, context):
    result = api.parse_wazuh_document(sample, **context)
    event, provenance = result.event, result.provenance
    assert event.schema_version == '2.0'
    assert event.source_type == 'wazuh'
    assert event.source_record_id == '1788874297.6897107'
    assert event.event_provider == 'Microsoft-Windows-Security-Auditing'
    assert event.hostname == 'LAB-WIN-001'
    assert event.asset_id == '901'
    assert event.username == 'LAB-WIN-001$'
    assert event.rule_id == '67027' and event.severity == 3
    assert event.process_name == r'C:\\Windows\\System32\\sppsvc.exe'
    assert event.parent_process_name == r'C:\\Windows\\System32\\services.exe'
    assert event.command_line == r'C:\\Windows\\system32\\sppsvc.exe'
    assert event.ingested_at.isoformat() == context['ingested_at']
    assert event.event_id == provenance.event_id == SAMPLE_ID
    assert event.raw_event_hash == provenance.raw_event_hash == SAMPLE_HASH
    assert event.raw_event_ref == 'win4688.sanitized.json#record=1'
    assert provenance.collector_agent_id == '901'
    assert provenance.collector_agent_name == 'LAB-WIN-001'
    assert provenance.collector_manager_name == 'lab-manager-001'
    assert provenance.mapping_version == 'wazuh-win4688-v2'
    assert provenance.timestamp_basis == 'windows.systemTime'
    assert provenance.timestamp_policy == 'lossless-nanosecond-v2'
    assert provenance.source_fraction_digits == 7
    assert provenance.record_index == 1
    for field in ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'event_action',
                  'file_path', 'file_hash', 'signature_id', 'technique_ids'):
        assert getattr(event, field) is None
    assert CanonicalEventV2.model_validate_json(event.model_dump_json()) == event
    with pytest.raises((ValueError, AttributeError, TypeError)):
        result.event = event
    with pytest.raises((ValueError, AttributeError, TypeError)):
        provenance.collection_mode = 'unknown'


@pytest.mark.parametrize('fraction', ['', '.1', '.12', '.123', '.1234', '.12345', '.123456', '.1234567', '.12345678', '.123456789', '.000000000'])
def test_all_timestamp_precisions(api, sample, context, fraction):
    raw = variant(sample, '_source.data.win.system.systemTime', f'2026-01-01T00:00:00{fraction}+07:00')
    result = api.parse_wazuh_document(raw, **context)
    assert result.event.timestamp.isoformat() == f'2025-12-31T17:00:00{fraction}Z'
    assert result.provenance.source_fraction_digits == max(0, len(fraction) - 1)


@pytest.mark.parametrize('value', [None, '', 'not-time', 123, True, '2026-01-01T00:00:00',
    '2026-01-01T00:00:00.1234567890Z', '2026-02-30T00:00:00Z',
    '2026-01-01T00:00:00-00:00', '0001-01-01T00:00:00+01:00'])
def test_no_time_fallback(api, sample, context, value):
    raw = variant(sample, '_source.data.win.system.systemTime', value)
    with pytest.raises(api.WazuhParseError) as caught:
        api.parse_wazuh_document(raw, **context)
    assert caught.value.diagnostic.code == ('missing_event_time' if value is None else 'invalid_event_time')
    assert caught.value.diagnostic.field_path == '_source.data.win.system.systemTime'


def test_missing_time_is_an_error(api, sample, context):
    with pytest.raises(api.WazuhParseError) as caught:
        api.parse_wazuh_document(variant(sample, '_source.data.win.system.systemTime', omit=True), **context)
    assert caught.value.diagnostic.code == 'missing_event_time'


@pytest.mark.parametrize('mode,asset', [('direct', '901'), ('forwarded', None), ('unknown', None)])
def test_collector_is_not_necessarily_origin(api, sample, context, mode, asset):
    raw = variant(sample, '_source.agent.name', 'collector-only')
    result = api.parse_wazuh_document(raw, **(context | {'collection_mode': mode}))
    assert result.event.asset_id == asset
    assert result.event.hostname == 'LAB-WIN-001'
    assert result.provenance.collector_agent_name == 'collector-only'
    missing_host = api.parse_wazuh_document(variant(raw, '_source.data.win.system.computer', omit=True), **context)
    assert missing_host.event.hostname is None


def test_creator_user_and_new_pid_not_target_or_other_pids(api, sample, context):
    raw = variant(sample, '_source.data.win.eventdata.subjectUserName', 'creator-test')
    raw = variant(raw, '_source.data.win.eventdata.targetUserName', 'target-test')
    event = api.parse_wazuh_document(raw, **context).event
    assert event.username == 'creator-test'
    assert event.process_id == 7892  # not parent 676 or system.processID 4


OPTIONALS = [
    ('_source.id', 'source_record_id'), ('_source.agent.id', 'asset_id'),
    ('_source.data.win.system.computer', 'hostname'),
    ('_source.data.win.eventdata.subjectUserName', 'username'),
    ('_source.data.win.eventdata.newProcessName', 'process_name'),
    ('_source.data.win.eventdata.newProcessId', 'process_id'),
    ('_source.data.win.eventdata.parentProcessName', 'parent_process_name'),
    ('_source.data.win.eventdata.commandLine', 'command_line'),
    ('_source.rule.id', 'rule_id'), ('_source.rule.level', 'severity'),
]


@pytest.mark.parametrize('path,field', OPTIONALS)
@pytest.mark.parametrize('omit', [False, True])
def test_absent_fields_stay_null(api, sample, context, path, field, omit):
    event = api.parse_wazuh_document(variant(sample, path, omit=omit), **context).event
    assert getattr(event, field) is None


@pytest.mark.parametrize('path', ['_source.agent', '_source.manager', '_source.rule', '_source.data.win.eventdata'])
@pytest.mark.parametrize('omit', [False, True])
def test_absent_optional_containers(api, sample, context, path, omit):
    result = api.parse_wazuh_document(variant(sample, path, omit=omit), **context)
    assert result.event.schema_version == '2.0'


@pytest.mark.parametrize('path,value,code', [
    ('_source', None, 'missing_source'), ('_source', [], 'invalid_field'),
    ('_source.data', [], 'invalid_field'), ('_source.data.win', None, 'invalid_field'),
    ('_source.data.win.system', None, 'invalid_field'),
    ('_source.data.win.system.providerName', None, 'invalid_field'),
    ('_source.data.win.system.providerName', 'other', 'unsupported_profile'),
    ('_source.data.win.system.channel', 'other', 'unsupported_profile'),
    ('_source.data.win.system.eventID', '4104', 'unsupported_profile'),
    ('_source.data.win.system.eventID', 4688, 'invalid_field'),
    ('_source.agent', [], 'invalid_field'), ('_source.manager', 1, 'invalid_field'),
    ('_source.rule', [], 'invalid_field'), ('_source.data.win.eventdata', [], 'invalid_field'),
    ('_source.agent.id', 901, 'invalid_field'), ('_source.agent.name', True, 'invalid_field'),
    ('_source.manager.name', {}, 'invalid_field'), ('_source.id', 123, 'invalid_field'),
    ('_source.rule.id', True, 'invalid_field'), ('_source.rule.id', 1.2, 'invalid_field'),
    ('_source.rule.id', -1, 'invalid_field'), ('_source.rule.level', '3', 'invalid_field'),
    ('_source.rule.level', True, 'invalid_field'), ('_source.rule.level', -1, 'invalid_field'),
    ('_source.data.win.eventdata.commandLine', [], 'invalid_field'),
])
def test_bad_mapped_values_fail_instead_of_becoming_null(api, sample, context, path, value, code):
    with pytest.raises(api.WazuhParseError) as caught:
        api.parse_wazuh_document(variant(sample, path, value), **context)
    assert caught.value.diagnostic.code == code
    assert caught.value.diagnostic.field_path == path


@pytest.mark.parametrize('pid,want', [('0x0', 0), ('0XfF', 255), ('0x0001', 1)])
def test_hex_pid(api, sample, context, pid, want):
    assert api.parse_wazuh_document(variant(sample, '_source.data.win.eventdata.newProcessId', pid), **context).event.process_id == want


@pytest.mark.parametrize('pid', ['', '0x', '7892', 7892, True, ' 0x1', '0x-1', '0x1g', '0x' + 'f' * 127])
def test_bad_pid(api, sample, context, pid):
    with pytest.raises(api.WazuhParseError) as caught:
        api.parse_wazuh_document(variant(sample, '_source.data.win.eventdata.newProcessId', pid), **context)
    assert caught.value.diagnostic.code == 'invalid_field'


@pytest.mark.parametrize('field,value', [('source_ref', '../secret.json'), ('source_ref', ''),
    ('source_ref', 'a' * 129), ('source_ref', 'a.json\n'), ('source_ref', 1),
    ('environment_id', ''), ('environment_id', ' \t'), ('environment_id', '\ud800'),
    ('ingested_at', None), ('ingested_at', '2026-01-01'),
    ('collection_mode', None), ('collection_mode', []), ('collection_mode', 'DIRECT')])
def test_invalid_context(api, sample, context, field, value):
    with pytest.raises(api.WazuhParseError) as caught:
        api.parse_wazuh_document(sample, **(context | {field: value}))
    assert caught.value.diagnostic.code == 'invalid_context'
    assert caught.value.diagnostic.field_path == field


def test_identity_raw_bytes_and_ingestion_context(api, sample, context):
    original = api.parse_wazuh_document(sample, **context)
    assert original.event.event_id == SAMPLE_ID
    for raw in (sample + b'\n', b'\xef\xbb\xbf' + sample, b' ' + sample):
        changed = api.parse_wazuh_document(raw, **context)
        assert changed.event.raw_event_hash == hashlib.sha256(raw).hexdigest()
        assert changed.event.event_id != original.event.event_id
    for changed_context in (context | {'source_ref': 'different.json'}, context | {'environment_id': 'other-lab'}):
        assert api.parse_wazuh_document(sample, **changed_context).event.event_id != SAMPLE_ID
    for changed_context in (context | {'ingested_at': '2026-01-01T00:00:00Z'}, context | {'collection_mode': 'forwarded'}):
        assert api.parse_wazuh_document(sample, **changed_context).event.event_id == SAMPLE_ID
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == SAMPLE_HASH


def test_loader_reads_exact_bytes_without_modifying_file(api, sample, context, tmp_path):
    path = tmp_path / 'unit.json'
    path.write_bytes(sample)
    result = api.load_wazuh_document(path, **context)
    assert result.event.event_id == SAMPLE_ID
    assert path.read_bytes() == sample
    path.write_bytes(b' ' * (256 * 1024 + 1))
    with pytest.raises(api.WazuhParseError) as caught:
        api.load_wazuh_document(path, **context)
    assert caught.value.diagnostic.code == 'input_too_large'


def test_error_privacy_for_validation_and_io(api, sample, context, tmp_path):
    raw = variant(sample, '_source.data.win.system.systemTime', 'SECRET-TIMESTAMP')
    for operation in (lambda: api.parse_wazuh_document(raw, **context),
                      lambda: api.load_wazuh_document(tmp_path / 'SECRET-PATH.json', **context)):
        with pytest.raises(api.WazuhParseError) as caught:
            operation()
        assert 'SECRET' not in str(caught.value)
        # Traceback source-code lines may contain literals from the caller; error
        # causes/contexts are suppressed and the diagnostic itself is value-free.
        assert caught.value.__suppress_context__
        assert 'SECRET' not in repr(caught.value.diagnostic)


@pytest.mark.parametrize('pid', ['0x' + 'f' * 107, hex(10 ** 128)])
def test_pid_conversion_cannot_exceed_canonical_numeric_budget(api, sample, context, pid):
    raw = variant(sample, '_source.data.win.eventdata.newProcessId', pid)
    with pytest.raises(api.WazuhParseError) as caught:
        api.parse_wazuh_document(raw, **context)
    assert caught.value.diagnostic.code == 'invalid_field'
    assert caught.value.diagnostic.field_path == '_source.data.win.eventdata.newProcessId'


@pytest.mark.parametrize('pid', ['0x0', hex(10 ** 128 - 1), '0x' + '0' * 125 + '1'])
def test_accepted_pid_round_trips_through_canonical_reader(api, sample, context, pid):
    from aegis_verify.canonical_io import parse_canonical_event_json
    event = api.parse_wazuh_document(variant(sample, '_source.data.win.eventdata.newProcessId', pid), **context).event
    assert parse_canonical_event_json(event.model_dump_json()) == event
