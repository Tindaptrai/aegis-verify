"""Real sanitized alert derivatives; flow inputs below are artificial unit data."""
import hashlib
import json
from pathlib import Path

import pytest

from aegis_verify.connectors import suricata
from aegis_verify.canonical_io import parse_canonical_event_json

FIXTURES = Path(__file__).resolve().parents[2] / 'tests/fixtures/suricata'
CONTEXT = dict(source_ref='eve-test.jsonl', environment_id='unit-lab',
               sensor_id='sensor-lab-1', deployment_mode='ids', ingested_at='2026-09-10T00:00:00Z')


def encode(obj):
    return json.dumps(obj, separators=(',', ':')).encode() + b'\n'


def fixture(name='wan'):
    return (FIXTURES / f'eve-{name}.sanitized.jsonl').read_bytes()


def parse(raw, **changes):
    return suricata.parse_suricata_eve_jsonl(raw, **(CONTEXT | changes))


def altered(path, value=None, *, omit=False, name='wan'):
    obj = json.loads(fixture(name))
    keys = path.split('.')
    parent = obj
    for key in keys[:-1]:
        parent = parent[key]
    if omit:
        parent.pop(keys[-1], None)
    else:
        parent[keys[-1]] = value
    return encode(obj)


def artificial_flow(**changes):
    # Deliberately not a derivative of an alert; never presented as lab evidence.
    obj = dict(timestamp='2026-01-01T07:00:02.123456789+0700', event_type='flow',
        flow_id=12345678901234567, src_ip='192.0.2.1', dest_ip='198.51.100.1',
        src_port=12345, dest_port=443, proto='TCP', app_proto='tls',
        flow=dict(start='2026-01-01T07:00:00.123456789+0700',
                  end='2026-01-01T07:00:01.123456789+0700', alerted=True,
                  pkts_toserver=5, pkts_toclient=3, bytes_toserver=120, bytes_toclient=90,
                  state='closed', reason='timeout', action='pass'))
    obj.update(changes)
    return obj


def test_direct_alert_uses_source_time_and_icmp_semantics():
    assert hasattr(suricata, 'parse_suricata_eve_jsonl'), 'Direct EVE API is not implemented'
    record, = parse(fixture())
    e, p = record.event, record.provenance
    assert record.status == 'parsed' and record.reason is None
    assert e.timestamp.isoformat() == '2026-04-03T14:33:28.714277Z'
    assert e.signature_id == '2100366' and e.rule_id is None and e.source_record_id is None
    assert e.src_port is e.dst_port is None
    assert p.icmp_type == 8 and p.icmp_code == 0
    assert p.source_src_port == p.source_dst_port == 0
    assert p.flow_id_raw == '100000000000001'
    assert p.sensor_id == 'sensor-lab-1' and p.action_scope == 'alert_rule'
    assert p.source_fraction_digits == 6 and p.event_type == 'alert'
    assert p.warnings == () and p.record_index == p.line_start == p.line_end == 1
    assert p.raw_event_ref == e.raw_event_ref == 'eve-test.jsonl#L1-L1'
    assert p.raw_event_hash == e.raw_event_hash == hashlib.sha256(fixture()).hexdigest()
    assert e.event_id == 'suricata:eve-evidence-v1:20168dbad90e2b487b1532ba1d70a0f01416e41789585a8f6930fbcbef6e20f6'
    assert parse_canonical_event_json(e.model_dump_json()) == e


@pytest.mark.parametrize('name,proto,sid,port', [('lan','TCP','2210054',443), ('mgmt','UDP','2231000',56097)])
def test_real_network_direction_is_not_replaced_by_nested_flow(name, proto, sid, port):
    record, = parse(fixture(name))
    assert record.event.protocol == proto and record.event.signature_id == sid
    assert record.event.src_port == port
    assert record.event.hostname is None and record.event.username is None
    assert record.provenance.signature_id == sid


def test_flow_record_time_action_and_metadata_do_not_invent_alert():
    record, = parse(encode(artificial_flow()))
    e, p = record.event, record.provenance
    assert e.timestamp.isoformat() == '2026-01-01T00:00:02.123456789Z'
    assert p.flow_start.isoformat() == '2026-01-01T00:00:00.123456789Z'
    assert p.flow_end.isoformat() == '2026-01-01T00:00:01.123456789Z'
    assert p.flow_id_raw == '12345678901234567'
    assert p.flow_alerted is True and p.flow_pkts_toserver == 5
    assert p.flow_bytes_toclient == 90 and p.flow_reason == 'timeout'
    assert e.signature_id is e.rule_id is e.severity is e.source_record_id is None
    assert p.action_scope == 'flow' and p.source_flow_action == 'pass'
    assert e.event_action == 'allowed' and p.source_alert_action is None
    assert parse_canonical_event_json(e.model_dump_json()) == e


@pytest.mark.parametrize('action,expected', [(None,None), ('pass','allowed'), ('drop','blocked')])
@pytest.mark.parametrize('mode', ['ids','ips','unknown'])
def test_flow_action_scope_and_ids_warning(action, expected, mode):
    obj = artificial_flow(); obj['flow']['action'] = action
    record, = parse(encode(obj), deployment_mode=mode)
    assert record.event.event_action == expected
    assert record.provenance.warnings == (('ids_blocked_action_requires_review',) if mode=='ids' and expected=='blocked' else ())


def test_alert_action_not_overridden_by_flow_action_or_fake_wazuh_fields():
    obj = json.loads(fixture('lan')); obj['flow']['action']='drop'
    obj['rule']={'id':'fake'}; obj['id']='fake'; obj['agent']={'name':'fake'}
    record, = parse(encode(obj))
    assert record.event.event_action == 'allowed' and record.provenance.source_flow_action == 'drop'
    assert record.provenance.warnings == ()
    assert record.event.rule_id is record.event.source_record_id is record.event.hostname is None


def test_mixed_jsonl_keeps_skips_and_physical_line_identity():
    raw = fixture() + b' \t\r\n' + fixture('dmz') + fixture('lan').rstrip(b'\n')
    result = parse(raw)
    assert [r.status for r in result] == ['parsed','skipped','skipped','parsed']
    assert [r.reason for r in result] == [None,'blank_line','unsupported_event_type',None]
    assert [r.provenance.record_index for r in result] == [1,2,3,4]
    assert result[1].event is result[2].event is None
    assert result[1].provenance.raw_event_hash == hashlib.sha256(b' \t\r\n').hexdigest()
    assert result[2].provenance.event_type == 'dns'
    assert result[3].event.raw_event_ref == 'eve-test.jsonl#L4-L4'
    assert parse(b'') == ()


def test_identity_uses_line_bytes_context_but_not_ingestion_or_mode():
    original, = parse(fixture())
    for change in ({'ingested_at':'2026-01-01T00:00:00Z'}, {'deployment_mode':'ips'}):
        assert parse(fixture(), **change)[0].event.event_id == original.event.event_id
    for change in ({'sensor_id':'sensor-lab-2'}, {'environment_id':'other'}, {'source_ref':'other.jsonl'}):
        assert parse(fixture(), **change)[0].event.event_id != original.event.event_id
    twice = parse(fixture()*2)
    assert twice[0].event.raw_event_hash == twice[1].event.raw_event_hash
    assert twice[0].event.event_id != twice[1].event.event_id
    for raw in (fixture().rstrip(b'\n'), b'\xef\xbb\xbf'+fixture(), fixture().replace(b'\n',b'\r\n')):
        record, = parse(raw)
        assert record.event.raw_event_hash == hashlib.sha256(raw).hexdigest()
        assert record.event.event_id != original.event.event_id
    assert parse(b'\xef\xbb\xbf'+fixture())[0].event.timestamp == original.event.timestamp


@pytest.mark.parametrize('value', [None,True,1,[], '', 'alert\n', 'SECRET TYPE', 'a'*65])
def test_invalid_event_selector(value):
    with pytest.raises(suricata.SuricataParseError) as e:
        parse(altered('event_type', value))
    assert e.value.diagnostic.field_path == 'event_type'
    assert e.value.diagnostic.line == e.value.diagnostic.record_index == 1


@pytest.mark.parametrize('tail,code', [(b'{\n','invalid_json'),(b'[]\n','invalid_root'),
    (b'{"secret":1,"secret":2}\n','duplicate_key'),(b'{"event_type":"dns","v":NaN}\n','invalid_number'),
    (b'{"event_type":"dns","secret":"\\ud800"}\n','invalid_unicode'),
    (b'\xff\n','invalid_encoding'),(b'\xef\xbb\xbf{}\n','invalid_bom')])
def test_error_on_later_line_is_safe_and_never_silently_skipped(tail, code):
    with pytest.raises(suricata.SuricataParseError) as e:
        parse(fixture()+tail)
    d=e.value.diagnostic
    assert d.code == code and d.line == d.record_index == 2
    assert 'secret' not in str(e.value) and e.value.__suppress_context__


@pytest.mark.parametrize('width', range(10))
def test_direct_precision(width):
    frac='.'+'123456780'[:width] if width else ''
    record, = parse(altered('timestamp','2026-01-01T00:00:00'+frac+'+0700'))
    assert record.event.timestamp.isoformat() == '2025-12-31T17:00:00'+frac+'Z'
    assert record.provenance.source_fraction_digits == width


@pytest.mark.parametrize('field,value', [('timestamp',None),('timestamp','2026-01-01T00:00:00-0000'),
    ('timestamp','2026-01-01T00:00:00.1234567890Z'),('flow_id',True),('flow_id',1.0),('flow_id','123'),
    ('src_ip',True),('src_ip','fe80::1%eth0'),('dest_port',65536),('icmp_type',256),('icmp_code',True),
    ('flow.pkts_toserver',True),('flow.pkts_toclient','1'),('flow.bytes_toclient',-1),
    ('flow.start','bad'),('flow.end','bad'),('flow.alerted',1),('flow.action','blocked'),
    ('flow.state',[]),('flow',[]),('alert',None),('alert.action','drop')])
def test_invalid_mapped_values_report_direct_paths(field, value):
    with pytest.raises(suricata.SuricataParseError) as e:
        parse(altered(field,value))
    assert e.value.diagnostic.field_path == field


@pytest.mark.parametrize('path,field', [('src_ip','src_ip'),('dest_port','dst_port'),('proto','protocol'),
    ('alert.signature_id','signature_id'),('alert.action','event_action'),('alert.severity','severity')])
@pytest.mark.parametrize('omit', [False,True])
def test_missing_optional_canonical_fields_stay_null(path, field, omit):
    record, = parse(altered(path,omit=omit,name='lan'))
    assert getattr(record.event,field) is None


@pytest.mark.parametrize('flow', [None,[],False])
def test_flow_event_requires_object(flow):
    with pytest.raises(suricata.SuricataParseError) as e:
        parse(encode(artificial_flow(flow=flow)))
    assert e.value.diagnostic.field_path == 'flow'


def test_flow_empty_object_does_not_guess_fields():
    record, = parse(encode(artificial_flow(flow={})))
    assert record.event.event_action is None
    assert record.provenance.flow_start is record.provenance.flow_alerted is None


@pytest.mark.parametrize('field,value', [('sensor_id','../secret'),('sensor_id',[]),('sensor_id',''),
    ('sensor_id','x'*129),('source_ref','x\n'),('environment_id','é'*65),
    ('ingested_at','2026-01-01'),('deployment_mode','IDS')])
def test_explicit_context_validation(field,value):
    with pytest.raises(suricata.SuricataParseError) as e:
        parse(fixture(),**{field:value})
    assert e.value.diagnostic.code == 'invalid_context' and e.value.diagnostic.field_path == field


def test_budgets_are_enforced_even_on_blank_or_unsupported_input():
    cases=[(b' '*(256*1024)+b'\n','input_too_large'),
           (b' '*(32*1024*1024+1),'total_input_too_large'),
           (b'\n'*100001,'max_records'),
           (b'{"event_type":"dns","v":'+b'['*20+b'0'+b']'*20+b'}','max_depth'),
           (b'{"event_type":"dns","v":'+b'9'*129+b'}','invalid_number'),
           (b'{"event_type":"dns","v":['+b'0,'*9999+b'0]}','max_nodes')]
    for raw,code in cases:
        with pytest.raises(suricata.SuricataParseError) as e:
            parse(raw)
        assert e.value.diagnostic.code == code
    with pytest.raises(suricata.SuricataParseError) as e:
        parse('{}')
    assert e.value.diagnostic.code == 'input_type'


def test_streaming_file_yields_before_late_error_and_releases_file(tmp_path):
    path=tmp_path/'input.jsonl'; path.write_bytes(fixture()+b'{\n')
    iterator=suricata.iter_suricata_eve_file(path,**CONTEXT)
    first=next(iterator)
    assert first.status == 'parsed'
    with pytest.raises(suricata.SuricataParseError) as e:
        next(iterator)
    assert e.value.diagnostic.line == 2
    path.rename(tmp_path/'renamed.jsonl')
    path.write_bytes(fixture()+fixture('dmz'))
    assert tuple(suricata.iter_suricata_eve_file(path,**CONTEXT)) == parse(path.read_bytes())
    iterator=suricata.iter_suricata_eve_file(path,**CONTEXT); next(iterator); iterator.close()
    path.unlink()


def test_loader_errors_and_boundaries(tmp_path):
    for path in (tmp_path/'SECRET',0,None):
        with pytest.raises(suricata.SuricataParseError) as e:
            tuple(suricata.iter_suricata_eve_file(path,**CONTEXT))
        assert e.value.diagnostic.code == 'io_error'
        assert 'SECRET' not in str(e.value) and e.value.__suppress_context__
    path=tmp_path/'large.jsonl'; path.write_bytes(b' '*(256*1024)+b'\n')
    with pytest.raises(suricata.SuricataParseError) as e:
        tuple(suricata.iter_suricata_eve_file(path,**CONTEXT))
    assert e.value.diagnostic.code == 'input_too_large'


def test_skips_are_immutable_and_unknown_bytes_remain_in_evidence():
    raw=encode({'event_type':'custom_extension','unknown':{'text':'kept'}})
    r,=parse(raw)
    assert r.event is None and r.reason == 'unsupported_event_type'
    assert r.provenance.raw_event_hash == hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError):
        r.status='parsed'
    with pytest.raises(ValueError):
        r.provenance.raw_event_hash='changed'


def test_exact_line_limit_and_total_stream_limit(tmp_path):
    # At the limit, a blank line is still counted and its complete bytes are hashed.
    line = b' '*(256*1024-1) + b'\n'
    record, = parse(line)
    assert record.reason == 'blank_line'
    assert record.provenance.raw_event_hash == hashlib.sha256(line).hexdigest()
    path = tmp_path/'size-limit.jsonl'
    with path.open('wb') as stream:
        for _ in range(128):
            stream.write(line)
        stream.write(b'\n')
    iterator = suricata.iter_suricata_eve_file(path, **CONTEXT)
    for index in range(1,129):
        assert next(iterator).provenance.line_start == index
    with pytest.raises(suricata.SuricataParseError) as e:
        next(iterator)
    assert e.value.diagnostic.code == 'total_input_too_large'
    assert e.value.diagnostic.line == 129


def test_stream_record_limit_includes_skipped_lines(tmp_path):
    path = tmp_path/'many-lines.jsonl'; path.write_bytes(b'\n'*100001)
    iterator = suricata.iter_suricata_eve_file(path, **CONTEXT)
    last = None
    with pytest.raises(suricata.SuricataParseError) as e:
        for last in iterator:
            pass
    assert last.provenance.line_start == 100000
    assert e.value.diagnostic.code == 'max_records'
    assert e.value.diagnostic.line == e.value.diagnostic.record_index == 100001


def test_lone_cr_does_not_split_two_records_and_unicode_separator_stays_in_string():
    with pytest.raises(suricata.SuricataParseError) as e:
        parse(fixture().rstrip(b'\n')+b'\r'+fixture())
    assert e.value.diagnostic.code == 'invalid_json' and e.value.diagnostic.line == 1
    obj=json.loads(fixture()); obj['unknown']='\u2028\u0085'
    raw=(json.dumps(obj,ensure_ascii=False)+'\n').encode()
    record,=parse(raw)
    assert record.provenance.line_start == record.provenance.line_end == 1
    assert record.event.raw_event_hash == hashlib.sha256(raw).hexdigest()


def test_direct_numeric_boundary_and_optional_flow_id():
    obj=artificial_flow(flow_id=10**127)
    obj['flow']['bytes_toserver']=10**127
    record,=parse(encode(obj))
    assert record.provenance.flow_id_raw == '1'+'0'*127
    assert record.provenance.flow_bytes_toserver == 10**127
    for omit in (True,False):
        raw=altered('flow_id',omit=omit)
        record,=parse(raw)
        assert record.provenance.flow_id_raw is None
        assert record.event.source_record_id is None
