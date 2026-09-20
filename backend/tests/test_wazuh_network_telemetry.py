"""Invented fixtures only; these tests are not evidence of a live scenario."""

import hashlib
import json
import traceback
from types import SimpleNamespace
from pathlib import Path

import pytest

from aegis_verify.connectors import wazuh


FIXTURE = (Path(__file__).resolve().parents[2] / 'tests/fixtures/wazuh/'
           'network-telemetry/sysmon3-archive.synthetic.json')
CONTEXT = dict(source_ref='synthetic-archive', environment_id='synthetic-env',
               ingested_at='2026-01-01T00:01:00Z', collection_mode='direct')


@pytest.fixture
def sample():
    return FIXTURE.read_bytes()


@pytest.fixture
def document(sample):
    return json.loads(sample)


def parse(raw, **overrides):
    api = getattr(wazuh, 'parse_wazuh_sysmon3_archive_record', None)
    assert callable(api), 'missing archive parser'
    return api(raw, **(CONTEXT | overrides))


def test_minimal_archive(sample):
    result = parse(sample)
    event = result.event
    assert event.timestamp.isoformat() == '2026-01-01T00:00:01.123Z'
    assert event.ingested_at.isoformat() == '2026-01-01T00:01:00Z'
    assert event.source_type == 'wazuh'
    assert event.event_action == 'observed'
    assert event.asset_id == '901'
    assert event.hostname == 'synthetic-endpoint'
    assert event.rule_id is None
    assert result.provenance.envelope == 'manager_archive'
    assert result.provenance.timestamp_basis == 'sysmon.utcTime'


@pytest.mark.parametrize('mixed', [False, True])
def test_reject_search_hit(document, mixed):
    value = dict(document, _source=None) if mixed else {'_source': document}
    with pytest.raises(wazuh.WazuhParseError):
        parse(json.dumps(value).encode())


@pytest.mark.parametrize('key,value', [
    ('providerName', 'Other'), ('channel', 'Security'), ('eventID', '1'),
    ('eventID', 3), ('providerName', None),
])
def test_reject_other_profiles(document, key, value):
    document['data']['win']['system'][key] = value
    with pytest.raises(wazuh.WazuhParseError):
        parse(json.dumps(document).encode())


def test_one_object_only(sample):
    for value in (b'[]', sample + sample):
        with pytest.raises(wazuh.WazuhParseError):
            parse(value)


def change(document, path, value=None, *, omit=False):
    parent = document
    parts = path.split('.')
    for part in parts[:-1]:
        parent = parent[part]
    if omit:
        parent.pop(parts[-1], None)
    else:
        parent[parts[-1]] = value
    return json.dumps(document).encode()


DATA = 'data.win.eventdata.'


def test_full_mapping_and_provenance(sample):
    result = parse(sample)
    event, provenance = result.event, result.provenance
    assert (str(event.src_ip), event.src_port, str(event.dst_ip), event.dst_port,
            event.protocol) == ('192.0.2.10', 49152, '198.51.100.20', 45002, 'udp')
    assert event.process_id == 4242
    assert event.process_name == r'C:\Synthetic\sender.exe'
    assert event.username == r'SYNTHETIC\operator'
    assert event.source_record_id == 'synthetic-archive-record'
    assert event.event_provider == 'Microsoft-Windows-Sysmon'
    for field in ('severity', 'rule_id', 'signature_id', 'command_line',
                  'parent_process_name', 'file_path', 'file_hash', 'technique_ids'):
        assert getattr(event, field) is None
    assert provenance.mapping_version == 'wazuh-sysmon3-archive-udp-v1'
    assert provenance.windows_event_id == '3'
    assert provenance.windows_record_id == '101'
    assert provenance.process_guid == '{00000000-0000-0000-0000-000000000001}'
    assert provenance.collector_agent_id == '901'
    assert provenance.collector_agent_name == 'synthetic-endpoint'
    assert provenance.collector_manager_name == 'synthetic-manager'
    assert provenance.source_fraction_digits == 3
    assert provenance.record_index == provenance.line_start == 1
    assert provenance.line_end == len(sample.splitlines())
    assert provenance.raw_event_ref == event.raw_event_ref == 'synthetic-archive#record=1'
    assert provenance.raw_event_hash == event.raw_event_hash == hashlib.sha256(sample).hexdigest()
    assert provenance.event_id == event.event_id
    identity = json.dumps(['wazuh-evidence-v1', 'synthetic-env', 'synthetic-archive',
                           1, hashlib.sha256(sample).hexdigest()], separators=(',', ':')).encode()
    assert event.event_id == 'wazuh:evidence-v1:' + hashlib.sha256(identity).hexdigest()
    assert result == parse(sample)
    assert parse(sample + b'\n').event.event_id != event.event_id
    assert parse(sample, source_ref='other').event.event_id != event.event_id
    assert parse(sample, environment_id='other').event.event_id != event.event_id
    for obj, field in ((result, 'event'), (provenance, 'envelope'), (event, 'src_port')):
        with pytest.raises((ValueError, AttributeError, TypeError)):
            setattr(obj, field, None)


@pytest.mark.parametrize('mode,asset', [('direct', '901'), ('forwarded', None), ('unknown', None)])
def test_collection_origin(sample, mode, asset):
    result = parse(sample, collection_mode=mode)
    assert result.event.asset_id == asset
    assert result.provenance.collection_mode == mode


@pytest.mark.parametrize('key,canonical', [
    ('sourcePort', 'src_port'), ('destinationPort', 'dst_port'),
    ('sourceIp', 'src_ip'), ('destinationIp', 'dst_ip'),
    ('processId', 'process_id'), ('image', 'process_name'), ('user', 'username'),
])
@pytest.mark.parametrize('omit', [False, True])
def test_optional_absence(document, key, canonical, omit):
    result = parse(change(document, DATA + key, omit=omit))
    assert getattr(result.event, canonical) is None


@pytest.mark.parametrize('field', ['sourcePort', 'destinationPort'])
@pytest.mark.parametrize('value,want', [('0', 0), ('65535', 65535), ('00042', 42)])
def test_port_values(document, field, value, want):
    event = parse(change(document, DATA + field, value)).event
    assert getattr(event, 'src_port' if field == 'sourcePort' else 'dst_port') == want


@pytest.mark.parametrize('field', ['sourcePort', 'destinationPort', 'processId'])
@pytest.mark.parametrize('value', [True, 42, '', ' 42', '-1', '1.5', '９', [], {}, '1' * 129])
def test_invalid_decimal(document, field, value):
    with pytest.raises(wazuh.WazuhParseError) as error:
        parse(change(document, DATA + field, value))
    assert error.value.diagnostic.field_path == DATA + field


@pytest.mark.parametrize('field', ['sourcePort', 'destinationPort'])
def test_port_overflow(document, field):
    with pytest.raises(wazuh.WazuhParseError):
        parse(change(document, DATA + field, '65536'))


def test_pid_decimal_limit(document):
    assert parse(change(document, DATA + 'processId', '9' * 128)).event.process_id == int('9' * 128)


@pytest.mark.parametrize('field', ['sourceIp', 'destinationIp'])
@pytest.mark.parametrize('value', [True, 123, '', 'hostname.test', '999.1.1.1',
                                   '::1', '192.0.2.10%eth0', ' 192.0.2.10', [], {}])
def test_ipv4_only(document, field, value):
    with pytest.raises(wazuh.WazuhParseError) as error:
        parse(change(document, DATA + field, value))
    assert error.value.diagnostic.field_path == DATA + field


@pytest.mark.parametrize('protocol', ['tcp', 'UDP', '', None, 17, True])
def test_udp_profile_only(document, protocol):
    with pytest.raises(wazuh.WazuhParseError):
        parse(change(document, DATA + 'protocol', protocol))


@pytest.mark.parametrize('fraction', ['', '.1', '.123', '.1234567', '.123456789'])
def test_exact_source_time(document, fraction):
    result = parse(change(document, DATA + 'utcTime', '2026-01-01 00:00:01' + fraction))
    assert result.event.timestamp.isoformat() == '2026-01-01T00:00:01' + fraction + 'Z'
    assert result.provenance.source_fraction_digits == len(fraction.lstrip('.'))


@pytest.mark.parametrize('value', [None, '', 123, True, '2026-02-30 00:00:01',
    '2026-01-01T00:00:01Z', '2026-01-01 00:00:01.1234567890',
    '２０２６-01-01 00:00:01', '2026-01-01 00:00:60', '2026-01-01 00:00:01Z'])
def test_invalid_time_has_no_fallback(document, value):
    with pytest.raises(wazuh.WazuhParseError):
        parse(change(document, DATA + 'utcTime', value))


def test_missing_time_has_no_fallback(document):
    with pytest.raises(wazuh.WazuhParseError) as error:
        parse(change(document, DATA + 'utcTime', omit=True))
    assert error.value.diagnostic.code == 'missing_event_time'


@pytest.mark.parametrize('path', ['data', 'data.win', 'data.win.system', 'data.win.eventdata'])
@pytest.mark.parametrize('value', [None, [], 'bad', 1])
def test_required_objects(document, path, value):
    with pytest.raises(wazuh.WazuhParseError) as error:
        parse(change(document, path, value))
    assert error.value.diagnostic.field_path == path


@pytest.mark.parametrize('path', ['id', 'agent.id', 'agent.name', 'manager.name',
    'data.win.system.computer', 'data.win.system.eventRecordID', DATA + 'image',
    DATA + 'user', DATA + 'processGuid'])
def test_optional_strings_reject_numbers(document, path):
    with pytest.raises(wazuh.WazuhParseError) as error:
        parse(change(document, path, 123))
    assert error.value.diagnostic.field_path == path


@pytest.mark.parametrize('parent', ['agent', 'manager', 'rule'])
@pytest.mark.parametrize('value', [[], 'bad', True])
def test_optional_objects_invalid(document, parent, value):
    document[parent] = value
    with pytest.raises(wazuh.WazuhParseError):
        parse(json.dumps(document).encode())


@pytest.mark.parametrize('parent', ['agent', 'manager'])
@pytest.mark.parametrize('omit', [False, True])
def test_optional_collectors_missing(document, parent, omit):
    result = parse(change(document, parent, omit=omit))
    if parent == 'agent':
        assert result.event.asset_id is None
        assert result.provenance.collector_agent_id is None
        assert result.provenance.collector_agent_name is None
    else:
        assert result.provenance.collector_manager_name is None


@pytest.mark.parametrize('rule,want', [
    ({'id': '123', 'level': 3}, ('123', 3)),
    ({'id': 123, 'level': 0}, ('123', 0)), ({}, (None, None)), (None, (None, None)),
])
def test_explicit_rule_only(document, rule, want):
    document['rule'] = rule
    event = parse(json.dumps(document).encode()).event
    assert (event.rule_id, event.severity) == want
    assert event.event_action == 'observed'


@pytest.mark.parametrize('rule', [{'id': True}, {'id': -1}, {'id': []},
                                {'level': True}, {'level': '3'}, {'level': -1}])
def test_invalid_rule(document, rule):
    document['rule'] = rule
    with pytest.raises(wazuh.WazuhParseError):
        parse(json.dumps(document).encode())


def test_preserve_strings_and_unknowns(document):
    path = r'C:\\Synthetic\\sender.exe'
    document['data']['win']['eventdata']['image'] = path
    document['full_log'] = 'unparsed-only-marker'
    document['unknown'] = {'nested': 'unparsed-only-marker'}
    raw = json.dumps(document).encode()
    result = parse(raw)
    assert result.event.process_name == path
    assert result.event.raw_event_hash == hashlib.sha256(raw).hexdigest()
    assert 'unparsed-only-marker' not in result.model_dump_json()


def test_safe_error(document):
    raw = change(document, DATA + 'sourcePort', 'sensitive-source-text')
    with pytest.raises(wazuh.WazuhParseError) as error:
        parse(raw)
    assert error.value.diagnostic.field_path == DATA + 'sourcePort'
    assert 'sensitive-source-text' not in str(error.value)
    assert 'sensitive-source-text' not in repr(error.value.diagnostic)
    assert 'sensitive-source-text' not in ''.join(traceback.format_exception(error.value))


@pytest.mark.parametrize('raw,code', [
    ('{}', 'input_type'), (b'\xff', 'invalid_encoding'),
    (b'{"a":1,"a":2}', 'duplicate_key'), (b'{"n":NaN}', 'invalid_number'),
    (b'{"n":Infinity}', 'invalid_number'), (b'{"n":1e999}', 'invalid_number'),
    (b'{"x":"\\ud800"}', 'invalid_unicode'),
    (b'{"x":' + b'1' * 129 + b'}', 'invalid_number'),
])
def test_strict_decoder(raw, code):
    with pytest.raises(wazuh.WazuhParseError) as error:
        parse(raw)
    assert error.value.diagnostic.code == code


def test_byte_boundary(sample):
    raw = sample + b' ' * (256 * 1024 - len(sample))
    assert parse(raw).event.raw_event_hash == hashlib.sha256(raw).hexdigest()
    with pytest.raises(wazuh.WazuhParseError) as error:
        parse(raw + b' ')
    assert error.value.diagnostic.code == 'input_too_large'


def test_depth_and_node_boundaries(document):
    for value in ('{"x":' * 21 + '0' + '}' * 21, json.dumps({'x': [0] * 10000})):
        with pytest.raises(wazuh.WazuhParseError) as error:
            parse(value.encode())
        assert error.value.diagnostic.code in ('max_depth', 'max_nodes')
    document['extra'] = [0] * 9000
    assert parse(json.dumps(document).encode()).event.protocol == 'udp'


@pytest.mark.parametrize('key,value', [('source_ref', '../private'), ('environment_id', ''),
    ('environment_id', '\ud800'), ('ingested_at', 'bad-time'), ('collection_mode', 'auto')])
def test_invalid_context(sample, key, value):
    with pytest.raises(wazuh.WazuhParseError) as error:
        parse(sample, **{key: value})
    assert error.value.diagnostic.code == 'invalid_context'


def test_legacy_search_hit_parser_still_rejects_archive(sample):
    with pytest.raises(wazuh.WazuhParseError) as error:
        wazuh.parse_wazuh_sysmon1_document(sample, **CONTEXT)
    assert error.value.diagnostic.code == 'missing_source'


def test_live_mapping_does_not_auto_dispatch_sysmon3(document):
    from aegis_verify.connectors.wazuh.live import LiveError, _map
    config = SimpleNamespace(agent_id='901', index='wazuh-alerts-*',
                             start='2026-01-01T00:00:00Z', end='2026-01-01T00:02:00Z')
    hit = {'_source': document, '_index': 'wazuh-alerts-synthetic'}
    with pytest.raises(LiveError, match='unsupported_profile'):
        _map(hit, config, 'synthetic-hit', '2026-01-01T00:03:00Z')


def test_manager_snapshot_still_excludes_sysmon3(sample):
    from aegis_verify.connectors.wazuh.manager_snapshot import (
        ManagerSnapshot, ManagerSnapshotScope, parse_manager_snapshots,
    )
    scope = ManagerSnapshotScope(
        agent_id='901', hostname='synthetic-endpoint', environment_id='synthetic-env',
        start='2026-01-01T00:00:00Z', end='2026-01-01T00:02:00Z',
        ingested_at='2026-01-01T00:03:00Z')
    document = json.loads(sample)
    document['decoder'] = {'name': 'windows_eventchannel'}
    raw = json.dumps(document, separators=(',', ':')).encode() + b'\n'
    snapshot = ManagerSnapshot('synthetic-snapshot', raw, hashlib.sha256(raw).hexdigest())
    result = parse_manager_snapshots((snapshot,), scope=scope)
    assert result.documents == ()
    assert len(result.ledger) == 1
    assert result.ledger[0].disposition == 'excluded'
    assert result.ledger[0].reason == 'outside_event'
