"""Synthetic canonical contract inputs, not source log evidence."""

import json

import pytest
from pydantic import ValidationError

from aegis_verify.models import CanonicalEvent


@pytest.fixture
def event_data():
    return {
        'schema_version': '2.0', 'event_id': 'unit-event',
        'timestamp': '2026-01-01T00:00:00.123456789Z',
        'ingested_at': '2026-01-01T00:00:01.123456700Z',
        'source_type': 'wazuh', 'environment_id': 'unit-lab',
        'raw_event_ref': 'unit-only/record:1', 'raw_event_hash': 'a' * 64,
    }


@pytest.fixture
def v2():
    from aegis_verify.models import CanonicalEventV2
    return CanonicalEventV2


def test_v2_json_keeps_nanos(v2, event_data):
    event = v2.model_validate(event_data)
    wire = event.model_dump_json()
    data = json.loads(wire)
    for field in ('timestamp', 'ingested_at'):
        assert data[field] == event_data[field]
        assert v2.model_validate_json(wire).model_dump()[field] == getattr(event, field)
        assert event.model_dump()[field] is getattr(event, field)
    assert event.timestamp.nanosecond == 123456789
    assert data['hostname'] is None
    assert event.raw_event_hash == event_data['raw_event_hash']
    assert event.raw_event_ref == event_data['raw_event_ref']
    with pytest.raises(ValidationError):
        event.timestamp = event.ingested_at


@pytest.mark.parametrize('field,value', [
    ('schema_version', '1.0'), ('timestamp', None), ('ingested_at', None),
    ('timestamp', '2026-01-01T00:00:00.1234567890Z'),
    ('ingested_at', '2026-01-01T00:00:00-00:00'),
    ('src_ip', 123), ('src_ip', 'not-an-ip'), ('src_port', True), ('dst_port', 65536),
    ('severity', -1), ('process_id', '4'), ('source_type', 'other'),
    ('event_action', 'detected'), ('hostname', '\ud800'),
    ('raw_event_hash', 'A' * 64), ('extra', 'unexpected'), ('technique_ids', ['']),
])
def test_v2_rejects_bad_fields_both_routes(v2, event_data, field, value):
    data = event_data | {field: value}
    with pytest.raises(ValidationError):
        v2.model_validate(data)
    with pytest.raises(ValidationError):
        v2.model_validate_json(json.dumps(data))


@pytest.mark.parametrize('field', ['event_id', 'timestamp', 'ingested_at', 'source_type', 'environment_id', 'raw_event_ref', 'raw_event_hash'])
def test_v2_required_fields(v2, event_data, field):
    del event_data[field]
    with pytest.raises(ValidationError):
        v2.model_validate(event_data)


def test_explicit_versions_and_schema(v2, event_data):
    with pytest.raises(ValidationError):
        CanonicalEvent.model_validate(event_data)
    with pytest.raises(ValidationError):
        v2.model_validate(event_data | {'schema_version': '1.0'})
    del event_data['schema_version']
    assert v2.model_validate(event_data).schema_version == '2.0'
    schema = v2.model_json_schema()
    assert schema['properties']['timestamp']['type'] == 'string'
    assert schema['properties']['ingested_at']['format'] == 'date-time'
    assert schema['additionalProperties'] is False


def test_deep_model_copy_keeps_timestamp_value(v2, event_data):
    event = v2.model_validate(event_data)
    assert event.model_copy(deep=True).model_dump_json() == event.model_dump_json()
