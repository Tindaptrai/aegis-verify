"""Closed offline Elastic intake contracts; no private or live lab dependency."""
from hashlib import sha256
import pytest

from aegis_verify.intake import IntakeError
from aegis_verify.intake.contracts import parse_manifest
from aegis_verify.intake.registry import canonical_source_type

KEYS = ('elastic-sysmon1-v1', 'elastic-sysmon3-v1',
        'elastic-powershell4104-v1', 'elastic-security-alert-v1')


def manifest(key, context=None):
    return {'bundle_schema_version': '0.1.0', 'environment_id': 'synthetic-lab-b',
            'files': [{'path': 'event.json', 'source_ref': 'synthetic-elastic',
                       'parser': key, 'sha256': sha256(b'{}').hexdigest(),
                       'context': context if context is not None else
                           {'ingested_at': '2026-01-01T00:02:00Z'}}]}


@pytest.mark.parametrize('key', KEYS)
def test_elastic_keys_have_explicit_closed_ingestion_context(key):
    parsed = parse_manifest(manifest(key))
    assert parsed.files[0].parser == key
    assert parsed.files[0].context.model_dump(mode='json') == {
        'ingested_at': '2026-01-01T00:02:00Z'}


@pytest.mark.parametrize('key', KEYS)
def test_elastic_registry_source_type_is_not_wazuh(key):
    assert canonical_source_type(key) == 'elastic'


@pytest.mark.parametrize('key', KEYS)
@pytest.mark.parametrize('extra', [{'collection_mode': 'direct'}, {'sensor_id': 'fake'},
                                 {'deployment_mode': 'ids'}, {'secret': 'do-not-echo'}])
def test_elastic_context_rejects_unreviewed_fields_without_values(key, extra):
    with pytest.raises(IntakeError) as error:
        parse_manifest(manifest(key, {'ingested_at': '2026-01-01T00:02:00Z', **extra}))
    assert 'do-not-echo' not in str(error.value)


@pytest.mark.parametrize('unknown', ['elastic', 'elastic-auto-v1', 'ELASTIC-sysmon1-v1'])
def test_no_auto_dispatch_parser_key(unknown):
    with pytest.raises(IntakeError):
        parse_manifest(manifest(unknown))


def test_exact_physical_line_extraction_is_declared_instead_of_claimed_native():
    value=manifest(KEYS[0])
    value['files'][0]['derived_from']={
        'parent_sha256': 'f'*64, 'extraction': 'physical-line-bytes-v1'}
    parsed=parse_manifest(value)
    assert parsed.files[0].derived_from.extraction=='physical-line-bytes-v1'
    assert parsed.files[0].derived_from.parent_sha256=='f'*64


def test_elastic_offline_connector_is_visible_without_claiming_live_health(tmp_path):
    from aegis_verify.dashboard import ReportStore
    from aegis_verify.dashboard.overview import build_system_status

    status = build_system_status(None, ReportStore(tmp_path), None,
                                 now='2026-01-01T00:00:00Z')
    component = next(c for c in status['components'] if c['id'] == 'connector_elastic')
    assert component['status'] == 'not_configured'
    assert component['reason'] == 'no_live_connector'
    assert component['details']['seen_in_reports'] is None


@pytest.mark.parametrize('code,key', [('1', KEYS[0]), ('3', KEYS[1]),
                                    ('4104', KEYS[2]), ('alert', KEYS[3])])
def test_elastic_dispatch_preserves_exact_bytes_and_ledger(tmp_path, code, key):
    from test_elastic_connector import alert_document, document, raw
    from aegis_verify.intake import load_bundle
    data = raw(alert_document() if code == 'alert' else document(code)) + b'\r\n'
    (tmp_path / 'event.json').write_bytes(data)
    value = manifest(key)
    value['environment_id'] = 'synthetic-env'
    value['files'][0]['sha256'] = sha256(data).hexdigest()
    result = load_bundle(tmp_path, parse_manifest(value))
    assert len(result.events) == len(result.ledger) == 1
    event, ledger = result.events[0], result.ledger[0]
    assert event.source_type == ledger.source_type == 'elastic'
    assert ledger.status == 'parsed' and ledger.parser == key
    assert ledger.event_id == event.event_id
    assert ledger.raw_event_hash == sha256(data).hexdigest() == event.raw_event_hash
    assert ledger.raw_event_ref == event.raw_event_ref == 'synthetic-elastic#record=1'
    assert ledger.line_start == ledger.line_end == 1
    assert (tmp_path / 'event.json').read_bytes() == data


def test_elastic_wrong_document_profile_stops_intake_without_raw_leak(tmp_path):
    from test_elastic_connector import alert_document, raw
    from aegis_verify.intake import load_bundle
    data = raw(alert_document())
    (tmp_path / 'event.json').write_bytes(data)
    value = manifest(KEYS[0]); value['environment_id'] = 'synthetic-env'
    value['files'][0]['sha256'] = sha256(data).hexdigest()
    with pytest.raises(IntakeError) as error:
        load_bundle(tmp_path, parse_manifest(value))
    assert error.value.code == 'parser_error'
    assert 'SYNTHETIC_SAFE_MARKER' not in str(error.value)
