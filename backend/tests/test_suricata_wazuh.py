"""Reviewed alert; artificial variants are test inputs, not incident evidence."""
import hashlib
import json
from pathlib import Path

import pytest

from aegis_verify.canonical_io import parse_canonical_event_json
from aegis_verify.models import CanonicalEventV2

FIXTURE = Path(__file__).resolve().parents[2] / 'tests/fixtures/suricata/suricata-wazuh-alert-001.sanitized.json'
RAW_HASH = '9c2bcf703b12233af60629881983ec4367ebbd9e7075d7517b828cf9b70b038c'


@pytest.fixture
def sample():
    return FIXTURE.read_bytes()


@pytest.fixture
def context():
    return dict(source_ref=FIXTURE.name, environment_id='unit-lab',
                ingested_at='2026-09-09T00:00:00Z', deployment_mode='ids')


def test_exact_source_time(sample, context):
    from aegis_verify.connectors.suricata import parse_suricata_wazuh_document
    result = parse_suricata_wazuh_document(sample, **context)
    assert result.event.timestamp.isoformat() == '2026-04-29T17:18:09.338512Z'
    assert result.event.src_port == 55237
    assert result.provenance.flow_id_raw == '100000000000001.000000'


@pytest.fixture
def api():
    from aegis_verify.connectors import suricata
    return suricata


def variant(raw, path, value=None, *, omit=False):
    obj = json.loads(raw)
    parts = path.split('.')
    parent = obj
    for key in parts[:-1]:
        parent = parent[key]
    if omit:
        parent.pop(parts[-1], None)
    else:
        parent[parts[-1]] = value
    return json.dumps(obj, ensure_ascii=True).encode()


def test_sample_mapping(api, sample, context):
    result = api.parse_suricata_wazuh_document(sample, **context)
    e, p = result.event, result.provenance
    assert type(e) is CanonicalEventV2
    assert e.source_type == e.event_provider == 'suricata'
    assert str(e.src_ip) == '192.0.2.30' and str(e.dst_ip) == '198.51.100.8'
    assert e.src_port == 55237 and e.dst_port == 443 and e.protocol == 'UDP'
    assert e.signature_id == '2231000' and e.rule_id == '86601' and e.severity == 3
    assert e.event_action == 'allowed' and p.source_alert_action == 'allowed'
    assert p.action_scope == 'alert_rule' and p.warnings == ()
    assert p.collector_agent_id == '911' and p.collector_agent_name == 'LAB-FW-001'
    assert p.collector_agent_ip == '192.0.2.1' and p.collector_manager_name == 'lab-manager-001'
    assert p.signature_gid == p.signature_rev == '1'
    assert p.signature_text == 'SURICATA QUIC failed decrypt'
    assert p.signature_category == 'Generic Protocol Command Decode'
    assert p.app_proto == 'quic' and p.in_iface == 'if-lab-1'
    assert p.source_fraction_digits == 6 and p.timestamp_basis == 'suricata.data.timestamp'
    assert p.mapping_version == 'suricata-wazuh-alert-v1'
    assert p.input_profile == 'wazuh-suricata-alert-v1' and p.deployment_mode == 'ids'
    assert p.source_record_namespace == 'wazuh.alert.id'
    assert e.source_record_id == 'lab-wazuh-suricata-001'
    assert p.wazuh_rule_id == e.rule_id and p.wazuh_rule_level == 3
    assert p.signature_id == e.signature_id
    assert p.event_id == e.event_id and p.raw_event_hash == e.raw_event_hash == RAW_HASH
    assert e.event_id == 'suricata:evidence-v1:559e130f8ef34149bad4588114937637a06784d9e14361d30fcda44c426593e0'
    assert e.raw_event_ref == FIXTURE.name + '#L1-L92'
    assert p.line_start == p.record_index == 1 and p.line_end == 92
    for field in ('hostname', 'asset_id', 'username', 'process_name', 'process_id',
                  'parent_process_name', 'command_line', 'file_path', 'file_hash',
                  'technique_ids'):
        assert getattr(e, field) is None
    assert parse_canonical_event_json(e.model_dump_json()) == e
    with pytest.raises((ValueError, AttributeError, TypeError)):
        p.deployment_mode = 'ips'
    with pytest.raises((ValueError, AttributeError, TypeError)):
        result.event = e


@pytest.mark.parametrize('width', range(10))
@pytest.mark.parametrize('offset', ['+0700', '+07:00'])
def test_time_precision_and_rollover(api, sample, context, width, offset):
    fraction = '.' + '123456780'[:width] if width else ''
    raw = variant(sample, '_source.data.timestamp', '2026-01-01T00:00:00' + fraction + offset)
    result = api.parse_suricata_wazuh_document(raw, **context)
    assert result.event.timestamp.isoformat() == '2025-12-31T17:00:00' + fraction + 'Z'
    assert result.provenance.source_fraction_digits == width


@pytest.mark.parametrize('value', [None, '', True, 1, [], 'bad',
    '2026-01-01T00:00:00', '2026-01-01T00:00:00-0000', '2026-01-01T00:00:00-00:00',
    '2026-02-30T00:00:00Z', '2026-01-01T00:00:00.1234567890Z', '0001-01-01T00:00:00+0100'])
def test_invalid_time_never_falls_back(api, sample, context, value):
    with pytest.raises(api.SuricataParseError) as error:
        api.parse_suricata_wazuh_document(variant(sample, '_source.data.timestamp', value), **context)
    assert error.value.diagnostic.code == ('missing_event_time' if value is None else 'invalid_event_time')
    assert error.value.diagnostic.field_path == '_source.data.timestamp'


OPTIONALS = [('src_ip', 'src_ip'), ('dest_ip', 'dst_ip'), ('src_port', 'src_port'),
             ('dest_port', 'dst_port'), ('proto', 'protocol'),
             ('alert.signature_id', 'signature_id'), ('alert.severity', 'severity'),
             ('alert.action', 'event_action')]


@pytest.mark.parametrize('path,field', OPTIONALS)
@pytest.mark.parametrize('omit', [False, True])
def test_absent_fields_no_flow_fallback(api, sample, context, path, field, omit):
    e = api.parse_suricata_wazuh_document(variant(sample, '_source.data.' + path, omit=omit), **context).event
    assert getattr(e, field) is None


@pytest.mark.parametrize('mode', ['ids', 'ips', 'unknown'])
def test_blocked_is_source_fact_with_ids_conflict(api, sample, context, mode):
    result = api.parse_suricata_wazuh_document(variant(sample, '_source.data.alert.action', 'blocked'), **(context | {'deployment_mode': mode}))
    assert result.event.event_action == 'blocked'
    assert result.provenance.deployment_mode == mode
    assert result.provenance.warnings == (('ids_blocked_action_requires_review',) if mode == 'ids' else ())


@pytest.mark.parametrize('value,want', [(0,0), ('0',0), ('00080',80), (65535,65535), ('65535',65535)])
def test_ports(api, sample, context, value, want):
    assert api.parse_suricata_wazuh_document(variant(sample, '_source.data.src_port', value), **context).event.src_port == want


@pytest.mark.parametrize('value', [True, False, -1, 65536, '65536', 1.0, '1.0', '1e1', '+1', ' 1', '1 ', '١', '', '0'*129, {}, []])
def test_invalid_ports(api, sample, context, value):
    with pytest.raises(api.SuricataParseError) as error:
        api.parse_suricata_wazuh_document(variant(sample, '_source.data.src_port', value), **context)
    assert error.value.diagnostic.field_path == '_source.data.src_port'


@pytest.mark.parametrize('value', ['2001:db8::1', '0.0.0.0', '192.0.2.5'])
def test_ip_text(api, sample, context, value):
    assert str(api.parse_suricata_wazuh_document(variant(sample, '_source.data.dest_ip', value), **context).event.dst_ip) == value


@pytest.mark.parametrize('value', [True, 123, '', '1.2.3.999', '192.0.2.1/24', ' 192.0.2.1', 'fe80::1%eth0', []])
def test_bad_ip_not_coerced(api, sample, context, value):
    with pytest.raises(api.SuricataParseError) as error:
        api.parse_suricata_wazuh_document(variant(sample, '_source.data.src_ip', value), **context)
    assert error.value.diagnostic.field_path == '_source.data.src_ip'


@pytest.mark.parametrize('value,want', [(1,'1'), ('000123','000123'), ('100000000000001.000000','100000000000001.000000'), (None,None)])
def test_flow_identity_not_float(api, sample, context, value, want):
    result = api.parse_suricata_wazuh_document(variant(sample, '_source.data.flow_id', value), **context)
    assert result.provenance.flow_id_raw == want
    assert result.event.source_record_id == 'lab-wazuh-suricata-001'


@pytest.mark.parametrize('value', [True, 1.0, -1, '-1', '1.01', '1e3', '1.', '', [], '1'*129])
def test_bad_flow_id(api, sample, context, value):
    with pytest.raises(api.SuricataParseError) as error:
        api.parse_suricata_wazuh_document(variant(sample, '_source.data.flow_id', value), **context)
    assert error.value.diagnostic.field_path == '_source.data.flow_id'


@pytest.mark.parametrize('path,value,code', [
    ('_source',None,'missing_source'), ('_source',[],'invalid_field'),
    ('_source.data',None,'invalid_field'), ('_source.data.alert',None,'invalid_field'),
    ('_source.data.event_type','flow','unsupported_profile'), ('_source.data.event_type',1,'invalid_field'),
    ('_source.rule.groups',['windows'],'unsupported_profile'), ('_source.rule.groups',[1],'invalid_field'),
    ('_source.rule.groups','suricata','invalid_field'), ('_source.rule',None,'invalid_field'),
    ('_source.agent',[],'invalid_field'), ('_source.manager',1,'invalid_field'),
    ('_source.data.alert.action','drop','invalid_field'), ('_source.data.alert.action',True,'invalid_field'),
    ('_source.data.alert.signature_id',1.0,'invalid_field'), ('_source.data.alert.signature_id','1e3','invalid_field'),
    ('_source.data.alert.gid',False,'invalid_field'), ('_source.data.alert.rev',-1,'invalid_field'),
    ('_source.data.alert.severity','3.0','invalid_field'), ('_source.rule.level',True,'invalid_field'),
    ('_source.data.alert.signature',[],'invalid_field'), ('_source.data.app_proto',{},'invalid_field'),
    ('_source.agent.name',3,'invalid_field'), ('_source.id',True,'invalid_field')])
def test_bad_fields(api, sample, context, path, value, code):
    with pytest.raises(api.SuricataParseError) as error:
        api.parse_suricata_wazuh_document(variant(sample, path, value), **context)
    assert error.value.diagnostic.code == code
    assert error.value.diagnostic.field_path == path


@pytest.mark.parametrize('field,value', [('source_ref','../secret'), ('source_ref','a\n'),
    ('source_ref','a'*129), ('source_ref',None), ('environment_id',''), ('environment_id',' '),
    ('environment_id','\ud800'), ('environment_id','a'*129), ('environment_id','é'*65),
    ('ingested_at',None), ('ingested_at','2026-01-01'), ('deployment_mode','IDS'), ('deployment_mode',[])])
def test_context(api, sample, context, field, value):
    with pytest.raises(api.SuricataParseError) as error:
        api.parse_suricata_wazuh_document(sample, **(context | {field:value}))
    assert error.value.diagnostic.code == 'invalid_context'
    assert error.value.diagnostic.field_path == field


@pytest.mark.parametrize('separator', [b'\n', b'\r\n', b'\r'])
def test_physical_line_reference(api, sample, context, separator):
    raw = separator.join(sample.splitlines()) + separator
    result = api.parse_suricata_wazuh_document(raw, **context)
    assert result.provenance.line_end == 92
    assert result.event.raw_event_hash == hashlib.sha256(raw).hexdigest()
    raw = raw + separator
    assert api.parse_suricata_wazuh_document(raw, **context).provenance.line_end == 93


def test_unicode_separator_is_not_a_physical_line(api, sample, context):
    obj = json.loads(sample)
    obj['_source']['unknown'] = '\u2028\u0085\u2029'
    raw = json.dumps(obj, ensure_ascii=False).encode()
    assert api.parse_suricata_wazuh_document(raw, **context).provenance.line_end == 1


def test_exact_evidence_and_context_identity(api, sample, context):
    original = api.parse_suricata_wazuh_document(sample, **context).event
    for raw in (b'\xef\xbb\xbf'+sample, sample+b'\n', variant(sample,'_source.unknown','retained')):
        event = api.parse_suricata_wazuh_document(raw, **context).event
        assert event.raw_event_hash == hashlib.sha256(raw).hexdigest()
        assert event.event_id != original.event_id
    for change in ({'ingested_at':'2026-01-01T00:00:00Z'}, {'deployment_mode':'unknown'}):
        assert api.parse_suricata_wazuh_document(sample, **(context | change)).event.event_id == original.event_id
    for change in ({'source_ref':'another.json'}, {'environment_id':'other'}):
        assert api.parse_suricata_wazuh_document(sample, **(context | change)).event.event_id != original.event_id
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == RAW_HASH


@pytest.mark.parametrize('raw,code', [(b'{"secret":1,"secret":2}','duplicate_key'),
    (b'{','invalid_json'), (b'[]','invalid_root'), (b'\xff','invalid_encoding'),
    (b'{"v":NaN}','invalid_number'), (b'{"v":"\\ud800"}','invalid_unicode'),
    (b' '*(256*1024+1),'input_too_large'), ('{}','input_type'),
    (b'{"a":'+b'['*20+b'0'+b']'*20+b'}','max_depth'),
    (b'{"a":['+b'0,'*9999+b'0]}','max_nodes')], ids=lambda value: value if isinstance(value, str) and len(value) < 30 else None if not isinstance(value, bytes) else 'raw-' + hashlib.sha256(value).hexdigest()[:8])
def test_decoder_errors_are_source_safe(api, context, raw, code):
    with pytest.raises(api.SuricataParseError) as error:
        api.parse_suricata_wazuh_document(raw, **context)
    assert error.value.diagnostic.code == code
    assert 'secret' not in str(error.value)
    assert error.value.__suppress_context__


def test_loader_and_error_redaction(api, sample, context, tmp_path):
    path = tmp_path/'sample.json'
    path.write_bytes(sample)
    assert api.load_suricata_wazuh_document(path, **context).event.raw_event_hash == RAW_HASH
    assert path.read_bytes() == sample
    for bad in (tmp_path/'SECRET-PATH', 0, None):
        with pytest.raises(api.SuricataParseError) as error:
            api.load_suricata_wazuh_document(bad, **context)
        assert error.value.diagnostic.code == 'io_error'
        assert 'SECRET' not in str(error.value) and error.value.__suppress_context__
    path.write_bytes(b' '*(256*1024+1))
    with pytest.raises(api.SuricataParseError) as error:
        api.load_suricata_wazuh_document(path, **context)
    assert error.value.diagnostic.code == 'input_too_large'


@pytest.mark.parametrize('path,fields', [
    ('_source.agent', ('collector_agent_id', 'collector_agent_name', 'collector_agent_ip')),
    ('_source.manager', ('collector_manager_name',)),
    ('_source.rule.id', ('wazuh_rule_id',)),
    ('_source.rule.level', ('wazuh_rule_level',)),
    ('_source.data.alert.gid', ('signature_gid',)),
    ('_source.data.alert.rev', ('signature_rev',)),
    ('_source.data.flow_id', ('flow_id_raw',)),
    ('_source.id', ()),
])
@pytest.mark.parametrize('omit', [False, True])
def test_optional_provenance_absence(api, sample, context, path, fields, omit):
    result = api.parse_suricata_wazuh_document(variant(sample, path, omit=omit), **context)
    for field in fields:
        assert getattr(result.provenance, field) is None
    if path == '_source.id':
        assert result.event.source_record_id is None
    if path == '_source.rule.id':
        assert result.event.rule_id is None


@pytest.mark.parametrize('path,value,field,want', [
    ('_source.data.alert.signature_id', '0'*128, 'signature_id', '0'*128),
    ('_source.data.alert.signature_id', 10**127, 'signature_id', str(10**127)),
    ('_source.data.alert.severity', '9'*128, 'severity', int('9'*128)),
    ('_source.data.alert.severity', 10**127, 'severity', 10**127),
    ('_source.rule.id', 10**127, 'rule_id', str(10**127)),
])
def test_accepted_numeric_width_boundary(api, sample, context, path, value, field, want):
    event = api.parse_suricata_wazuh_document(variant(sample, path, value), **context).event
    assert getattr(event, field) == want
    assert parse_canonical_event_json(event.model_dump_json()) == event


@pytest.mark.parametrize('value,accepted', [('1'*118 + '.000000000', True),
                                         ('1.0000000000', False),
                                         ('1'*119 + '.000000000', False)])
def test_flow_text_boundaries(api, sample, context, value, accepted):
    raw = variant(sample, '_source.data.flow_id', value)
    if accepted:
        assert api.parse_suricata_wazuh_document(raw, **context).provenance.flow_id_raw == value
    else:
        with pytest.raises(api.SuricataParseError) as error:
            api.parse_suricata_wazuh_document(raw, **context)
        assert error.value.diagnostic.field_path == '_source.data.flow_id'
