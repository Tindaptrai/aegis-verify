"""Real sanitized Lab C alert_json lines and explicitly artificial boundary inputs."""
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address, ip_network
import json
from pathlib import Path

import pytest

from aegis_verify.canonical_io import parse_canonical_event_json
from aegis_verify.connectors import snort
from aegis_verify.connectors.snort._mapping import ACTIONS
from aegis_verify.evidence import hash_raw_event

FIXTURES = Path(__file__).resolve().parents[2] / 'tests/fixtures/snort'
CONTEXT = dict(source_ref='alert-test.jsonl', environment_id='unit-lab', sensor_id='sensor-lab-1',
               deployment_mode='ids', ingested_at='2026-10-06T00:00:00Z')
ICMP_LINE, UDP_LINE, TCP_LINE = 1, 4, 7
DOCUMENTATION = ip_network('192.0.2.0/24')


def manifest():
    path = FIXTURES / 'manifest.json'
    assert path.is_file(), 'reviewed derivative manifest is required'
    return json.loads(path.read_text(encoding='utf-8'))


def fixture_bytes():
    return (FIXTURES / manifest()['file']).read_bytes()


def fixture_line(number):
    return fixture_bytes().split(b'\n')[number - 1] + b'\n'


def source(number=ICMP_LINE):
    return json.loads(fixture_line(number))


def encode(obj):
    # Artificial input: Snort's own spacing is not required by JSON or by the parser.
    return json.dumps(obj, separators=(', ', ' : ')).encode() + b'\n'


def changed(mutate, number=ICMP_LINE):
    obj = source(number)
    mutate(obj)
    return encode(obj)


def parse(raw, **changes):
    return snort.parse_snort_alert_json(raw, **(CONTEXT | changes))


def diagnostic(raw, **changes):
    with pytest.raises(snort.SnortParseError) as caught:
        parse(raw, **changes)
    return caught.value.diagnostic


def reordered(obj):
    items = list(obj.items())
    items[0], items[1] = items[1], items[0]
    obj.clear()
    obj.update(items)


def with_ports(obj):
    items = []
    for key, value in obj.items():
        items.append((key, value))
        if key == 'src_addr':
            items.append(('src_port', 1))
        if key == 'dst_addr':
            items.append(('dst_port', 2))
    obj.clear()
    obj.update(items)


def test_fixture_bytes_match_the_reviewed_manifest():
    document = manifest()
    raw = fixture_bytes()
    assert hash_raw_event(raw) == document['derivative_sha256']
    assert document['source_ref'] == f"snort-l0010-l0018-sha256-{document['derivative_sha256']}"
    assert raw.endswith(b'\n') and b'\r' not in raw
    lines = raw.split(b'\n')[:-1]
    assert len(lines) == len(document['lines']) == 9
    for number, (line, entry) in enumerate(zip(lines, document['lines']), start=1):
        assert entry['derivative_line'] == number and entry['source_line'] == number + 9
        assert hashlib.sha256(line + b'\n').hexdigest() == entry['derivative_line_sha256']
        assert entry['expected_status'] == 'parsed'
        obj = json.loads(line)
        assert {ip_address(obj[k]) in DOCUMENTATION for k in ('src_addr', 'dst_addr')} == {True}
    assert document['pinned_fields'].split() == list(snort.PINNED_FIELDS)


def test_real_lab_lines_map_to_canonical_events_without_inference():
    document = manifest()
    records = snort.parse_snort_alert_json(fixture_bytes(), source_ref=document['source_ref'],
                                           **document['parser_context'])
    assert [r.status for r in records] == ['parsed'] * 9
    for number, (record, entry) in enumerate(zip(records, document['lines']), start=1):
        event, prov, raw = record.event, record.provenance, source(number)
        assert (event.source_type, event.event_provider) == ('snort', 'snort')
        assert f'{prov.signature_gid}:{event.signature_id}:{prov.signature_rev}' == entry['expected_rule']
        assert event.protocol == entry['expected_proto'] == raw['proto']
        assert (str(event.src_ip), str(event.dst_ip)) == ('192.0.2.10', '192.0.2.1')
        if raw['proto'] in ('TCP', 'UDP'):
            assert (event.src_port, event.dst_port) == (raw['src_port'], raw['dst_port'])
        else:
            assert (event.src_port, event.dst_port) == (None, None)
        assert (event.event_action, prov.source_alert_action) == ('allowed', 'allow')
        assert (event.severity, prov.source_priority) == (None, 0)
        assert event.rule_id is None and event.hostname is None
        stamp = datetime.fromtimestamp(raw['seconds'], timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.')
        assert event.model_dump(mode='json')['timestamp'] == stamp + raw['timestamp'][-6:] + 'Z'
        assert event.timestamp.fractional_digits == prov.source_fraction_digits == 6
        assert (prov.timestamp_basis, prov.source_seconds) == ('alert_json.seconds', raw['seconds'])
        assert (prov.signature_text, prov.signature_category) == (raw['msg'], raw['class'])
        assert (prov.app_proto, prov.direction, prov.pkt_gen) == (raw['service'], raw['dir'], raw['pkt_gen'])
        assert (prov.pkt_len, prov.pkt_num) == (raw['pkt_len'], raw['pkt_num'])
        assert event.raw_event_ref == prov.raw_event_ref == f"{document['source_ref']}#L{number}-L{number}"
        assert event.raw_event_hash == entry['derivative_line_sha256']
        assert prov.line_start == prov.line_end == prov.record_index == number
        assert prov.warnings == ()
        assert parse_canonical_event_json(event.model_dump_json()) == event
    assert len({r.event.event_id for r in records}) == 9
    assert {r.provenance.pkt_gen for r in records} == {'raw', 'stream_tcp'}


def test_event_identity_is_deterministic_and_bound_to_context():
    raw = fixture_bytes()
    first = [r.event.event_id for r in parse(raw)]
    assert first == [r.event.event_id for r in parse(raw)]
    assert all(i.startswith('snort:alert-json-evidence-v1:') for i in first)
    for change in ({'sensor_id': 'sensor-lab-2'}, {'source_ref': 'other.jsonl'}, {'environment_id': 'lab-b'}):
        assert not set(first) & {r.event.event_id for r in parse(raw, **change)}


@pytest.mark.parametrize('mutate,code,field', [
    (lambda o: o.update(extra=1), 'unsupported_profile', None),
    (lambda o: o.pop('msg'), 'unsupported_profile', 'msg'),
    (lambda o: o.pop('seconds'), 'unsupported_profile', 'seconds'),
    (lambda o: o.pop('service'), 'unsupported_profile', 'service'),
    (reordered, 'unsupported_profile', None),
    (lambda o: o.update(timestamp='10/06-11:11:07.428947'), 'unsupported_profile', 'timestamp'),
    (lambda o: o.update(timestamp='26/10/06-18:11:07.428947'), 'invalid_event_time', 'timestamp'),
    (lambda o: o.update(timestamp='26/13/06-11:11:07.428947'), 'invalid_event_time', 'timestamp'),
    (lambda o: o.update(timestamp='26/10/06-11:11:07.4289'), 'invalid_event_time', 'timestamp'),
    (lambda o: o.update(timestamp=1791285067), 'invalid_event_time', 'timestamp'),
    (lambda o: o.update(seconds='1791285067'), 'invalid_event_time', 'seconds'),
    (lambda o: o.update(seconds=True), 'invalid_event_time', 'seconds'),
    (lambda o: o.update(seconds=1791285067.0), 'invalid_event_time', 'seconds'),
    (lambda o: o.update(seconds=-1), 'invalid_event_time', 'seconds'),
    (lambda o: o.update(src_addr='192.0.2.300'), 'invalid_field', 'src_addr'),
    (lambda o: o.update(dst_addr='fe80::1%eth0'), 'invalid_field', 'dst_addr'),
    (lambda o: o.update(dst_addr=3221225985), 'invalid_field', 'dst_addr'),
    (lambda o: o.update(rule='1:1000001'), 'invalid_field', 'rule'),
    (lambda o: o.update(rule='1:4294967296:1'), 'invalid_field', 'rule'),
    (lambda o: o.update(rule=' 1:1000001:1'), 'invalid_field', 'rule'),
    (lambda o: o.update(action='alert'), 'invalid_field', 'action'),
    (lambda o: o.update(action='ALLOW'), 'invalid_field', 'action'),
    (lambda o: o.update(dir='OUT'), 'invalid_field', 'dir'),
    (lambda o: o.update(proto='icmp'), 'invalid_field', 'proto'),
    (lambda o: o.update(pkt_gen='Raw'), 'invalid_field', 'pkt_gen'),
    (lambda o: o.update(service='un known'), 'invalid_field', 'service'),
    (lambda o: o.update(priority=-1), 'invalid_field', 'priority'),
    (lambda o: o.update(priority=True), 'invalid_field', 'priority'),
    (lambda o: o.update(pkt_num=-1), 'invalid_field', 'pkt_num'),
    (lambda o: o.update(pkt_len='60'), 'invalid_field', 'pkt_len'),
    (lambda o: o.update(msg=''), 'invalid_field', 'msg'),
    (lambda o: o.update({'class': None}), 'invalid_field', 'class'),
    (with_ports, 'invalid_field', 'src_port'),
    (lambda o: o.pop('dst_addr'), 'invalid_field', 'dst_addr'),
])
def test_deviation_from_the_pinned_profile_is_rejected_with_a_fixed_code(mutate, code, field):
    d = diagnostic(changed(mutate))
    assert (d.code, d.field_path, d.line, d.record_index) == (code, field, 1, 1)


def test_tcp_and_udp_require_both_ports():
    for number in (UDP_LINE, TCP_LINE):
        for key in ('src_port', 'dst_port'):
            assert diagnostic(changed(lambda o: o.pop(key), number)).code == 'invalid_field'
        assert diagnostic(changed(lambda o: o.update(dst_port=65536), number)).field_path == 'dst_port'


def test_alert_without_an_ip_header_is_an_explicit_skip():
    def no_ip(obj):
        obj.pop('src_addr')
        obj.pop('dst_addr')
        obj['proto'] = 'ARP'
    record, = parse(changed(no_ip))
    assert (record.status, record.reason, record.event) == ('skipped', 'no_ip_header', None)
    assert record.provenance.signature_id == '1000001' and record.provenance.event_id is None


@pytest.mark.parametrize('action', sorted(ACTIONS))
@pytest.mark.parametrize('mode', ['ids', 'ips', 'unknown'])
def test_every_snort_action_string_maps_only_definite_outcomes(action, mode):
    record, = parse(changed(lambda o: o.update(action=action)), deployment_mode=mode)
    assert record.event.event_action == ACTIONS[action]
    assert record.provenance.source_alert_action == action
    blocked = ACTIONS[action] == 'blocked' and mode == 'ids'
    assert record.provenance.warnings == (('ids_blocked_action_requires_review',) if blocked else ())


def test_non_zero_priority_is_kept_as_severity():
    record, = parse(changed(lambda o: o.update(priority=3)))
    assert (record.event.severity, record.provenance.source_priority) == (3, 3)


def test_json_errors_keep_line_numbers_and_no_partial_result():
    good = fixture_line(ICMP_LINE)
    for bad, code in ((b'{"seconds" : 1\n', 'invalid_json'), (b'["not", "an", "object"]\n', 'invalid_root'),
                      (b'{"seconds" : 1, "seconds" : 2}\n', 'duplicate_key')):
        d = diagnostic(good + bad)
        assert (d.code, d.line, d.record_index) == (code, 2, 2)


def test_bom_only_on_the_first_line_and_blank_lines_are_explicit_skips():
    good = fixture_line(ICMP_LINE)
    first, = parse(b'\xef\xbb\xbf' + good)
    assert first.status == 'parsed'
    assert first.event.raw_event_hash == hashlib.sha256(b'\xef\xbb\xbf' + good).hexdigest()
    assert diagnostic(good + b'\xef\xbb\xbf' + good).code == 'invalid_bom'
    records = parse(good + b'\n' + good)
    assert [(r.status, r.reason) for r in records] == [('parsed', None), ('skipped', 'blank_line'), ('parsed', None)]
    assert records[1].provenance.raw_event_ref == 'alert-test.jsonl#L2-L2'


@pytest.mark.parametrize('change,field', [
    ({'source_ref': 'bad ref'}, 'source_ref'),
    ({'sensor_id': ''}, 'sensor_id'),
    ({'deployment_mode': 'IDS'}, 'deployment_mode'),
    ({'ingested_at': '2026-10-06T00:00:00'}, 'ingested_at'),
    ({'environment_id': ' '}, 'environment_id'),
])
def test_caller_context_is_explicit_and_validated(change, field):
    d = diagnostic(fixture_bytes(), **change)
    assert (d.code, d.field_path) == ('invalid_context', field)


def test_input_bounds_and_type():
    assert diagnostic('text').code == 'input_type'
    assert diagnostic(b'{' + b' ' * (256 * 1024) + b'}\n').code == 'input_too_large'


def test_file_api_matches_bytes_api_and_hides_io_details(tmp_path):
    path = tmp_path / 'alert_json.txt'
    path.write_bytes(fixture_bytes())
    assert tuple(snort.iter_snort_alert_json_file(path, **CONTEXT)) == parse(fixture_bytes())
    with pytest.raises(snort.SnortParseError) as caught:
        tuple(snort.iter_snort_alert_json_file(tmp_path / 'missing.txt', **CONTEXT))
    assert caught.value.diagnostic.code == 'io_error'
