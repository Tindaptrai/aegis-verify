"""Real sanitized Lab C filterlog lines and explicitly artificial boundary inputs.

Artificial inputs are real fixture lines with one or two cells changed; they are
not lab evidence.
"""
import hashlib
from ipaddress import ip_address, ip_network
import json
from pathlib import Path

import pytest

from aegis_verify.canonical_io import parse_canonical_event_json
from aegis_verify.connectors import opnsense
from aegis_verify.connectors.opnsense import parser as opnsense_parser
from aegis_verify.connectors.opnsense._mapping import map_filterlog_line
from aegis_verify.evidence import hash_raw_event

FIXTURES = Path(__file__).resolve().parents[2] / 'tests/fixtures/opnsense'
MAIN = 'lab-c-20261006.sanitized.log'
BAD = 'concatenated-l1707.sanitized.log'
SOURCE_LINES = [2, 4, 43, 44, 72, 418, 986, 988, 2055, 2069, 11390, 11396, 11498, 11499, 11500, 11557]
CONTEXT = dict(source_ref='filterlog-test.log', environment_id='unit-lab', sensor_id='fw-lab-1',
               ingested_at='2026-10-06T12:00:00Z', source_year=2026, source_utc_offset='+00:00')
# Positions in the main fixture (1-based).
UDP_V4, TCP_V4, ICMP_V4, UDP_V6, ICMP_V6 = 1, 12, 16, 5, 8
AGENT_IN, AGENT_OUT, ICMPV6_IN = 14, 15, 9
DOCUMENTATION = [ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]
CONSTANTS = {ip_address(a) for a in ('0.0.0.0', '255.255.255.255', 'ff02::1', 'ff02::2',
                                     'ff02::1:2', 'fe80::1', 'fe80::2')}


def manifest():
    path = FIXTURES / 'manifest.json'
    assert path.is_file(), 'reviewed derivative manifest is required'
    return json.loads(path.read_text(encoding='utf-8'))


def entry(name):
    return next(item for item in manifest()['fixtures'] if item['file'] == name)


def main_bytes():
    return (FIXTURES / MAIN).read_bytes()


def text(number):
    return main_bytes().split(b'\n')[number - 1].decode('ascii')


def changed(number, **cells):
    """Return fixture line `number` with payload cells replaced by index."""
    head, separator, payload = text(number).partition(': ')
    values = payload.split(',')
    for index, value in cells.items():
        values[int(index)] = value
    return head + separator + ','.join(values)


def parse(raw, **changes):
    return opnsense.parse_opnsense_filterlog(raw, **(CONTEXT | changes))


def diagnostic(raw, **changes):
    with pytest.raises(opnsense.OpnSenseParseError) as caught:
        parse(raw, **changes)
    return caught.value.diagnostic


def mapped(line):
    context = opnsense.make_context(**CONTEXT)
    return map_filterlog_line(line, context)


def mapping_error(line):
    with pytest.raises(opnsense.OpnSenseParseError) as caught:
        mapped(line)
    return caught.value


def test_fixture_bytes_match_the_reviewed_manifest():
    document = manifest()
    assert document['source_sha256'] == 'a4218341e967728444f001cff05e87437ac5fcc7a2aef61c0b3706bc3d0ddddd'
    assert document['source_physical_lines'] == 12811
    assert document['parser'] == 'opnsense-filterlog-bsd-v1'
    assert [item['file'] for item in document['fixtures']] == [MAIN, BAD]
    for item in document['fixtures']:
        raw = (FIXTURES / item['file']).read_bytes()
        assert hash_raw_event(raw) == item['derivative_sha256']
        assert item['source_ref'].endswith('-sha256-' + item['derivative_sha256'])
        assert raw.endswith(b'\n') and b'\r' not in raw
        physical = raw.split(b'\n')[:-1]
        assert [line['line'] for line in item['lines']] == list(range(1, len(physical) + 1))
        for line, data in zip(item['lines'], physical):
            assert hashlib.sha256(data + b'\n').hexdigest() == line['derivative_line_sha256']
            assert len(bytes.fromhex(line['source_line_sha256'])) == 32
    assert [line['source_line'] for line in entry(MAIN)['lines']] == SOURCE_LINES
    assert [line['source_line'] for line in entry(BAD)['lines']] == [1707]


def test_fixture_holds_only_aliases_and_protocol_constants():
    document = manifest()
    for substitution in document['substitutions']:
        address = ip_address(substitution['replacement'])
        assert address in CONSTANTS or any(address in network for network in DOCUMENTATION)
    records = parse(main_bytes())
    for record in records:
        assert record.event.hostname == 'fixture-fw'
        for address in (record.event.src_ip, record.event.dst_ip):
            assert address in CONSTANTS or any(address in network for network in DOCUMENTATION)


def test_real_lines_map_to_the_manifest_expectations():
    document = manifest()
    item = entry(MAIN)
    records = opnsense.parse_opnsense_filterlog(
        main_bytes(), source_ref=item['source_ref'], **document['parser_context'])
    assert [record.status for record in records] == ['parsed'] * 16
    for record, line in zip(records, item['lines']):
        event, provenance, expect = record.event, record.provenance, line['expect']
        assert (provenance.interface, event.event_action.value, provenance.direction,
                provenance.ip_version, event.protocol, event.rule_id) == (
            expect['interface'], expect['event_action'], expect['direction'],
            expect['ip_version'], expect['protocol'], expect['rule_id'])
        assert event.source_type.value == 'opnsense'
        assert event.event_provider == 'OPNsense-filterlog'
        assert provenance.raw_event_ref == f"{item['source_ref']}#L{line['line']}-L{line['line']}"
        assert provenance.raw_event_hash == event.raw_event_hash == line['derivative_line_sha256']
        assert provenance.syslog_pri == '134' and provenance.reason == 'match'
        assert provenance.timestamp_basis == 'bsd_syslog_with_caller_context'
        assert provenance.warnings == ('year_and_offset_supplied_by_caller',)
        assert provenance.nat_context is None
        assert provenance.input_profile == 'opnsense-filterlog-bsd-v1'
        assert parse_canonical_event_json(event.model_dump_json()) == event


def test_probe_ping_and_agent_connection_keep_source_values_only():
    records = parse(main_bytes())
    ping = records[ICMP_V4 - 1].event.model_dump(mode='json')
    absent = ('source_record_id', 'asset_id', 'username', 'process_name', 'process_id',
              'parent_process_name', 'command_line', 'file_path', 'file_hash',
              'signature_id', 'severity', 'technique_ids', 'session_key')
    assert {key: ping[key] for key in absent} == dict.fromkeys(absent)
    assert {key: ping[key] for key in ('timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
                                        'protocol', 'event_action', 'rule_id', 'hostname')} == {
        'timestamp': '2026-10-06T11:11:52Z', 'src_ip': '192.0.2.10', 'src_port': None,
        'dst_ip': '192.0.2.220', 'dst_port': None, 'protocol': 'icmp',
        'event_action': 'blocked', 'rule_id': 'f18da9d8-ba44-4a26-8909-effe55135cb6',
        'hostname': 'fixture-fw'}
    provenance = records[ICMP_V4 - 1].provenance
    assert (provenance.rule_number, provenance.interface, provenance.direction,
            provenance.protocol_id, provenance.protocol_text, provenance.timestamp_text) == (
        '86', 'em2', 'in', '1', 'icmp', 'Oct  6 11:11:52')
    entering, leaving = records[AGENT_IN - 1], records[AGENT_OUT - 1]
    for record in (entering, leaving):
        assert (record.event.src_ip, record.event.src_port, record.event.dst_ip,
                record.event.dst_port, record.event.protocol, record.event.event_action.value) == (
            ip_address('192.0.2.10'), 61713, ip_address('192.0.2.220'), 1514, 'tcp', 'allowed')
    assert (entering.provenance.interface, entering.provenance.direction) == ('em2', 'in')
    assert (leaving.provenance.interface, leaving.provenance.direction) == ('em1', 'out')
    assert entering.event.rule_id == 'd1819b64-84ca-4f1d-ab68-d3b28b196d0d'
    assert leaving.event.rule_id == 'fae559338f65e11c53669fc3642c93c2'


def test_ipv6_layouts_map_ports_only_for_udp():
    records = parse(main_bytes())
    udp = records[UDP_V6 - 1]
    assert (str(udp.event.src_ip), udp.event.src_port, str(udp.event.dst_ip), udp.event.dst_port,
            udp.event.protocol, udp.provenance.ip_version, udp.provenance.protocol_id) == (
        'fe80::1', 546, 'ff02::1:2', 547, 'udp', '6', '17')
    for number in (ICMP_V6, ICMPV6_IN):
        event = records[number - 1].event
        assert event.protocol == 'ipv6-icmp'
        assert event.src_port is event.dst_port is None
    assert str(records[ICMPV6_IN - 1].event.src_ip) == 'fe80::2'
    assert records[ICMPV6_IN - 1].provenance.direction == 'in'


def test_event_identity_is_deterministic_and_bound_to_evidence_context():
    first = main_bytes().split(b'\n')[0] + b'\n'
    record = parse(first)[0]
    identity = ['opnsense-filterlog-evidence-v1', 'unit-lab', 'fw-lab-1', 'filterlog-test.log',
                1, hashlib.sha256(first).hexdigest(), 2026, '+00:00']
    digest = hashlib.sha256(json.dumps(identity, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
    assert record.event.event_id == record.provenance.event_id == 'opnsense:filterlog-evidence-v1:' + digest
    assert parse(first, ingested_at='2027-01-01T00:00:00Z')[0].event.event_id == record.event.event_id
    for change in (dict(environment_id='other-lab'), dict(sensor_id='fw-lab-2'),
                   dict(source_ref='other.log'), dict(source_year=2025),
                   dict(source_utc_offset='+07:00')):
        assert parse(first, **change)[0].event.event_id != record.event.event_id
    twice = parse(first + first)
    assert twice[0].event.event_id != twice[1].event.event_id


def test_caller_offset_converts_the_bsd_time_to_utc():
    first = main_bytes().split(b'\n')[0] + b'\n'
    assert parse(first)[0].event.timestamp.isoformat() == '2026-10-06T03:21:29Z'
    assert parse(first, source_utc_offset='+07:00')[0].event.timestamp.isoformat() == '2026-10-05T20:21:29Z'


def test_concatenated_collector_line_fails_the_whole_read_with_its_position(tmp_path):
    bad = (FIXTURES / BAD).read_bytes()
    assert bad.count(b'<134>') == 2 and bad.count(b'fixture-fw') == 2
    found = diagnostic(bad)
    assert (found.code, found.field_path, found.line, found.record_index) == ('invalid_field', 'label', 1, 1)
    assert (entry(BAD)['expected_code'], entry(BAD)['expected_field']) == ('invalid_field', 'label')
    combined = main_bytes() + bad
    assert diagnostic(combined).line == 17
    path = tmp_path / 'combined.log'
    path.write_bytes(combined)
    seen = []
    with pytest.raises(opnsense.OpnSenseParseError) as caught:
        for record in opnsense.iter_opnsense_filterlog_file(path, **CONTEXT):
            seen.append(record)
    assert len(seen) == 16 and caught.value.line == 17
    assert 'fixture' not in str(caught.value) and '198.51.100' not in str(caught.value)


def test_bundle_intake_stops_at_the_concatenated_line(tmp_path):
    from aegis_verify.intake import IntakeError
    from aegis_verify.intake.contracts import parse_manifest
    from aegis_verify.intake.loader import load_bundle

    raw = main_bytes() + (FIXTURES / BAD).read_bytes()
    (tmp_path / 'filterlog.log').write_bytes(raw)
    bundle = parse_manifest({
        'bundle_schema_version': '0.1.0', 'environment_id': 'unit-lab',
        'files': [{'path': 'filterlog.log', 'source_ref': 'opnsense-log',
                   'parser': 'opnsense-filterlog-bsd-v1', 'sha256': hashlib.sha256(raw).hexdigest(),
                   'context': {'ingested_at': '2026-10-06T12:00:00Z', 'sensor_id': 'fw-lab-1',
                               'source_year': 2026, 'source_utc_offset': '+00:00'}}],
    })
    with pytest.raises(IntakeError) as caught:
        load_bundle(tmp_path, bundle)
    assert (caught.value.code, caught.value.line) == ('parser_error', 17)


def test_header_without_pri_hostname_or_pid_is_accepted_and_kept_as_absent():
    line = text(UDP_V4)
    for variant, pri, hostname in (
        (line[len('<134>'):], None, 'fixture-fw'),
        (line.replace('fixture-fw ', '', 1), '134', None),
        (line.replace('filterlog[9869]', 'filterlog', 1), '134', 'fixture-fw'),
        (line.replace('Oct  6', 'Oct 16', 1), '134', 'fixture-fw'),
    ):
        fields, metadata, reason = mapped(variant)
        assert reason is None
        assert (metadata['syslog_pri'], fields['hostname']) == (pri, hostname)
        assert fields['src_port'] == 64578 and fields['event_action'] == 'allowed'


@pytest.mark.parametrize('line,code,field', [
    ('<192>' + text(UDP_V4)[5:], 'invalid_field', 'pri'),
    ('<013>' + text(UDP_V4)[5:], 'invalid_field', 'pri'),
    ('<0134>' + text(UDP_V4)[5:], 'malformed_header', None),
    ('<>' + text(UDP_V4)[5:], 'malformed_header', None),
    (text(UDP_V4).replace('filterlog[9869]', 'filterdns[9869]'), 'malformed_header', None),
    (text(UDP_V4).replace('filterlog[9869]', 'filterlog[x]'), 'malformed_header', None),
    (text(UDP_V4).replace(']: ', ']:'), 'malformed_header', None),
    (text(UDP_V4).replace('fixture-fw ', 'fixture fw '), 'malformed_header', None),
    ('<134>1 2026-10-06T03:21:29+00:00 fixture-fw filterlog 9869 - - ' + text(UDP_V4).partition(': ')[2],
     'malformed_header', None),
    (text(UDP_V4).replace('Oct  6', 'Feb 30'), 'invalid_timestamp', 'timestamp'),
    (text(UDP_V4).replace('Oct  6', 'Okt  6'), 'invalid_timestamp', 'timestamp'),
    (text(UDP_V4).replace('03:21:29', '24:21:29'), 'invalid_timestamp', 'timestamp'),
])
def test_headers_outside_the_observed_bsd_form_are_rejected(line, code, field):
    error = mapping_error(line)
    assert (error.code, error.field_path) == (code, field)


@pytest.mark.parametrize('index,token,code,field', [
    (0, '', 'missing_field', 'rule_number'), (0, '-1', 'invalid_field', 'rule_number'),
    (1, '1.0', 'invalid_field', 'subrule'), (2, 'a b', 'invalid_field', 'anchor'),
    (3, '1000000001', 'invalid_field', 'label'),
    (3, 'FAE559338F65E11C53669FC3642C93C2', 'invalid_field', 'label'),
    (3, 'fae559338f65e11c53669fc3642c93c', 'invalid_field', 'label'),
    (3, '15ea5b31cbf1409ebcdec61970e1d7a3x', 'invalid_field', 'label'),
    (4, '', 'missing_field', 'interface'), (5, '', 'missing_field', 'reason'),
    (6, 'rdr', 'unsupported_value', 'action'), (6, 'Pass', 'unsupported_value', 'action'),
    (7, 'both', 'unsupported_value', 'direction'),
    (8, '4.0', 'invalid_field', 'ip_version'), (8, '', 'missing_field', 'ip_version'),
])
def test_common_columns_are_validated_before_any_classification(index, token, code, field):
    error = mapping_error(changed(UDP_V4, **{str(index): token}))
    assert (error.code, error.field_path) == (code, field)


@pytest.mark.parametrize('number,index,token,code,field', [
    (TCP_V4, 9, '0x100', 'invalid_field', 'tos'), (TCP_V4, 10, '256', 'invalid_field', 'ecn'),
    (TCP_V4, 11, '256', 'invalid_field', 'ttl'), (TCP_V4, 12, '65536', 'invalid_field', 'ip_id'),
    (TCP_V4, 13, '-1', 'invalid_field', 'offset'), (TCP_V4, 14, 'D F', 'invalid_field', 'ip_flags'),
    (TCP_V4, 15, '256', 'invalid_field', 'protocol_id'),
    (TCP_V4, 15, '17', 'invalid_field', 'protocol_text'),
    (TCP_V4, 16, 'udp', 'invalid_field', 'protocol_text'),
    (TCP_V4, 17, '65536', 'invalid_field', 'length'),
    (TCP_V4, 18, '2001:db8::1', 'invalid_field', 'src_ip'),
    (TCP_V4, 18, '192.0.2.010', 'invalid_field', 'src_ip'),
    (TCP_V4, 18, '', 'missing_field', 'src_ip'),
    (TCP_V4, 19, 'host.invalid', 'invalid_field', 'dst_ip'),
    (TCP_V4, 20, '65536', 'invalid_field', 'src_port'), (TCP_V4, 20, '', 'missing_field', 'src_port'),
    (TCP_V4, 21, '+1', 'invalid_field', 'dst_port'), (TCP_V4, 22, '65536', 'invalid_field', 'data_length'),
    (TCP_V4, 23, 'X', 'invalid_field', 'tcp_flags'), (TCP_V4, 23, 'SS', 'invalid_field', 'tcp_flags'),
    (TCP_V4, 24, '4294967296', 'invalid_field', 'sequence'), (TCP_V4, 24, '1:', 'invalid_field', 'sequence'),
    (TCP_V4, 25, '4294967296', 'invalid_field', 'ack'), (TCP_V4, 26, '65536', 'invalid_field', 'window'),
    (TCP_V4, 27, '65536', 'invalid_field', 'urg'), (TCP_V4, 28, 'mss nop', 'invalid_field', 'tcp_options'),
    (UDP_V4, 21, '', 'missing_field', 'dst_port'),
    (ICMP_V4, 20, 'datalength=65536', 'invalid_field', 'data_length'),
    (ICMP_V4, 20, 'datalength=', 'invalid_field', 'data_length'),
    (ICMP_V4, 20, 'datalen=40', 'invalid_field', 'data_length'),
    (ICMP_V4, 20, '40', 'invalid_field', 'data_length'),
    (ICMP_V4, 20, '', 'missing_field', 'data_length'),
    (UDP_V6, 9, '0x100', 'invalid_field', 'traffic_class'),
    (UDP_V6, 10, '0x100000', 'invalid_field', 'flow_label'),
    (UDP_V6, 11, '256', 'invalid_field', 'hop_limit'),
    (UDP_V6, 12, 'tcp', 'invalid_field', 'protocol_text'),
    (UDP_V6, 14, '65536', 'invalid_field', 'length'),
    (UDP_V6, 15, '192.0.2.1', 'invalid_field', 'src_ip'),
    (UDP_V6, 15, 'fe80::1%em0', 'invalid_field', 'src_ip'),
    (UDP_V6, 16, 'ff02::1::2', 'invalid_field', 'dst_ip'),
    (UDP_V6, 17, '65536', 'invalid_field', 'src_port'),
    (ICMP_V6, 17, 'datalength=x', 'invalid_field', 'data_length'),
])
def test_layout_cells_are_strict(number, index, token, code, field):
    error = mapping_error(changed(number, **{str(index): token}))
    assert (error.code, error.field_path) == (code, field)
    assert '192.0.2' not in str(error) and 'fixture-fw' not in str(error)


@pytest.mark.parametrize('line,code', [
    (text(TCP_V4) + ',', 'invalid_field'), (text(TCP_V4).rsplit(',', 1)[0], 'missing_field'),
    (text(UDP_V4) + ',1', 'invalid_field'), (text(UDP_V6) + ',', 'invalid_field'),
    (text(ICMP_V4) + ',x', 'invalid_field'), (text(ICMP_V6).rsplit(',', 1)[0], 'missing_field'),
    (text(UDP_V4).split(',4,')[0] + ',4', 'missing_field'),
    (','.join(text(UDP_V4).split(',')[:8]), 'missing_field'),
])
def test_missing_or_extra_columns_are_errors_not_nulls(line, code):
    assert mapping_error(line).code == code


@pytest.mark.parametrize('line,reason', [
    (changed(UDP_V4, **{'8': '5'}), 'unsupported_ip_version'),
    (changed(UDP_V6, **{'12': 'tcp', '13': '6'}), 'unsupported_protocol'),
    (changed(UDP_V4, **{'15': '2', '16': 'igmp'}), 'unsupported_protocol'),
    (changed(UDP_V4, **{'15': '112', '16': 'carp'}), 'unsupported_protocol'),
    (changed(ICMP_V4, **{'15': '58', '16': 'ipv6-icmp'}), 'unsupported_protocol'),
    (changed(ICMP_V6, **{'12': 'icmp', '13': '1'}), 'unsupported_protocol'),
])
def test_layouts_without_a_real_sample_are_explicit_skips(line, reason):
    fields, metadata, actual = mapped(line)
    assert fields is None and actual == reason
    assert metadata['interface'] in {'em0', 'em1', 'em2', 'em3'} and metadata['rule_number']
    records = parse((line + '\n').encode())
    assert records[0].status == 'skipped' and records[0].reason == reason
    assert records[0].event is None and records[0].provenance.event_id is None


@pytest.mark.parametrize('line', [
    changed(UDP_V4, **{'8': '5', '6': 'rdr'}),
    changed(UDP_V4, **{'8': '5', '3': 'not-a-label'}),
    changed(UDP_V6, **{'12': 'tcp', '13': '17'}),
])
def test_skips_still_require_valid_common_columns(line):
    with pytest.raises(opnsense.OpnSenseParseError):
        mapped(line)


def test_empty_label_and_case_of_protocol_name():
    fields, metadata, reason = mapped(changed(UDP_V4, **{'3': ''}))
    assert reason is None and fields['rule_id'] is None and metadata['label'] is None
    fields, metadata, _ = mapped(changed(UDP_V4, **{'16': 'UDP'}))
    assert fields['protocol'] == 'udp' and metadata['protocol_text'] == 'UDP'
    fields, _, _ = mapped(changed(TCP_V4, **{'23': 'FSRPAUEW', '24': '4294967295:0', '20': '0'}))
    assert fields['src_port'] == 0


@pytest.mark.parametrize('token', ['"q"', "a'b", 'a\tb', 'a\x00b', 'a\x7fb', 'a\u0085b', 'a﻿b', 'a b'])
def test_quotes_controls_and_separators_are_rejected(token):
    error = mapping_error(changed(TCP_V4, **{'28': token}))
    assert error.code == 'invalid_field' and error.field_path is None


def test_framing_blank_bom_crlf_and_encoding():
    first = main_bytes().split(b'\n')[0]
    records = parse(b'\n   \n' + first + b'\n')
    assert [(r.status, r.reason) for r in records] == [('skipped', 'blank_line')] * 2 + [('parsed', None)]
    with_bom = parse(b'\xef\xbb\xbf' + first + b'\n')[0]
    crlf = parse(first + b'\r\n')[0]
    plain = parse(first + b'\n')[0]
    no_newline = parse(first)[0]
    assert len({with_bom.event.raw_event_hash, crlf.event.raw_event_hash,
                plain.event.raw_event_hash, no_newline.event.raw_event_hash}) == 4
    assert with_bom.event.src_port == crlf.event.src_port == plain.event.src_port == 64578
    assert diagnostic(first + b'\n\xef\xbb\xbf' + first + b'\n').code == 'invalid_bom'
    found = diagnostic(first + b'\n' + first.replace(b'fixture-fw', b'fixture-\xff') + b'\n')
    assert (found.code, found.line) == ('invalid_encoding', 2)


@pytest.mark.parametrize('change,field', [
    (dict(source_utc_offset='-00:00'), 'source_utc_offset'),
    (dict(source_utc_offset='+24:00'), 'source_utc_offset'),
    (dict(source_year=0), 'source_year'), (dict(source_year='2026'), 'source_year'),
    (dict(sensor_id='fw lab'), 'sensor_id'), (dict(source_ref=''), 'source_ref'),
    (dict(environment_id=' '), 'environment_id'), (dict(ingested_at='2026-10-06T12:00:00'), 'ingested_at'),
])
def test_caller_context_is_explicit_and_validated(change, field):
    found = diagnostic(main_bytes(), **change)
    assert (found.code, found.field_path) == ('invalid_context', field)


@pytest.mark.parametrize('name,limit,code', [
    ('MAX_LINE_BYTES', 100, 'input_too_large'),
    ('MAX_RECORDS', 15, 'max_records'),
    ('MAX_FILE_BYTES', 1000, 'total_input_too_large'),
])
def test_resource_limits_fail_safely(monkeypatch, name, limit, code):
    monkeypatch.setattr(opnsense_parser, name, limit)
    assert diagnostic(main_bytes()).code == code


@pytest.mark.parametrize('raw', [None, 'text', bytearray(b''), memoryview(b'')])
def test_bytes_api_rejects_non_bytes(raw):
    assert diagnostic(raw).code == 'input_type'


def test_file_api_matches_bytes_api_and_hides_io_details(tmp_path):
    path = tmp_path / 'filterlog.log'
    path.write_bytes(main_bytes())
    assert tuple(opnsense.iter_opnsense_filterlog_file(path, **CONTEXT)) == parse(main_bytes())
    for bad_path in (tmp_path / 'missing.log', 'private\x00path', 1):
        with pytest.raises(opnsense.OpnSenseParseError) as caught:
            tuple(opnsense.iter_opnsense_filterlog_file(bad_path, **CONTEXT))
        assert caught.value.code == 'io_error' and 'missing' not in str(caught.value)


def test_pfsense_parser_still_refuses_opnsense_labels():
    from aegis_verify.connectors.pfsense import PfSenseParseError, parse_pfsense_filterlog

    line = text(UDP_V4)[len('<134>'):].encode() + b'\n'
    with pytest.raises(PfSenseParseError) as caught:
        parse_pfsense_filterlog(line, source_ref='x.log', environment_id='unit-lab', sensor_id='fw',
                                ingested_at='2026-10-06T12:00:00Z', source_year=2026,
                                source_utc_offset='+00:00')
    assert caught.value.field_path == 'tracker'
