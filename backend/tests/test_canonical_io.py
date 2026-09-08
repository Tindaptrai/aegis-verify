"""Synthetic inputs for the bounded canonical wire boundary."""

from copy import deepcopy
import json
import traceback

import pytest

from aegis_verify.models import CanonicalEvent, CanonicalEventV2


@pytest.fixture
def api():
    from aegis_verify import canonical_io
    return canonical_io


@pytest.fixture
def data():
    return {
        'schema_version': '1.0', 'event_id': 'unit-event',
        'timestamp': '2026-01-01T00:00:00.123456Z',
        'ingested_at': '2026-01-01T00:00:01Z',
        'source_type': 'wazuh', 'environment_id': 'unit-lab',
        'raw_event_ref': 'unit-only/record:1', 'raw_event_hash': 'a' * 64,
    }


@pytest.mark.parametrize('version,model', [('1.0', CanonicalEvent), ('2.0', CanonicalEventV2)])
def test_dispatch_explicit_version_without_mutation(api, data, version, model):
    data['schema_version'] = version
    if version == '2.0':
        data['timestamp'] = '2026-01-01T00:00:00.123456789Z'
    original = deepcopy(data)
    assert type(api.parse_canonical_event(data)) is model
    assert type(api.parse_canonical_event_json(json.dumps(data))) is model
    assert api.parse_canonical_event_json(json.dumps(data).encode()).model_dump(mode='json')['timestamp'] == data['timestamp']
    assert data == original


@pytest.mark.parametrize('version', [None, True, 1, 2.0, '3.0', {}, [], 'SECRET-VERSION'])
def test_no_version_inference(api, data, version):
    with pytest.raises(api.CanonicalReadError) as caught:
        api.parse_canonical_event(data | {'schema_version': version})
    assert caught.value.code == 'unsupported_version'
    assert caught.value.field_path == 'schema_version'
    assert 'SECRET' not in str(caught.value)


def test_missing_version_and_default_constructor(api, data):
    del data['schema_version']
    assert CanonicalEvent.model_validate(data).schema_version == '1.0'
    with pytest.raises(api.CanonicalReadError):
        api.parse_canonical_event(data)


@pytest.mark.parametrize('raw', [
    b'\xff', b'\xff\xfe{\x00}\x00', '"text"', '[]', 'null', '{} trailing',
    '{"schema_version":"1.0","schema_version":"2.0"}',
    '{"nested":{"a":1,"a":2}}', '{"n":NaN}', '{"n":Infinity}',
    '{"n":-Infinity}', '{"n":1e999}', '{"n":' + '1' * 129 + '}',
    '{"n":1e' + '1' * 127 + '}', '{"x":"\\ud800"}', '{"\\udfff":0}',
    '[' * 33 + '0' + ']' * 33,
])
def test_rejects_unsafe_wire_inputs(api, raw):
    with pytest.raises(api.CanonicalReadError):
        api.parse_canonical_event_json(raw)


@pytest.mark.parametrize('value', [float('nan'), float('inf'), 10 ** 128, ('x',), {'x'}, object(), '\ud800'])
def test_dict_must_be_json_like(api, data, value):
    with pytest.raises(api.CanonicalReadError):
        api.parse_canonical_event(data | {'hostname': value})


def test_input_byte_limit_and_utf8_budget(api, data):
    for raw in (' ' * (1024 * 1024 + 1), b' ' * (1024 * 1024 + 1)):
        with pytest.raises(api.CanonicalReadError) as caught:
            api.parse_canonical_event_json(raw)
        assert caught.value.code == 'input_too_large'
    with pytest.raises(api.CanonicalReadError) as caught:
        api.parse_canonical_event(data | {'hostname': '\u00e9' * (1024 * 1024 // 2)})
    assert caught.value.code == 'input_too_large'


def test_depth_cycles_and_shared_subtrees(api, data):
    cycle = []
    cycle.append(cycle)
    with pytest.raises(api.CanonicalReadError) as caught:
        api.parse_canonical_event(data | {'x': cycle})
    assert caught.value.code == 'invalid_json'
    nested = []
    for _ in range(32):
        nested = [nested]
    with pytest.raises(api.CanonicalReadError) as caught:
        api.parse_canonical_event(data | {'x': nested})
    assert caught.value.code == 'input_too_deep'
    shared = []
    with pytest.raises(api.CanonicalReadError) as caught:
        api.parse_canonical_event(data | {'x': [shared, shared]})
    assert caught.value.code == 'invalid_event'  # not incorrectly reported as a cycle


def test_structural_characters_inside_string_do_not_count_as_depth(api, data):
    data['command_line'] = '"\\' + '[' * 100 + '{' * 100
    assert api.parse_canonical_event_json(json.dumps(data)).command_line == data['command_line']


def test_error_diagnostics_never_echo_values_or_unknown_keys(api, data):
    for changed in ({'timestamp': 'SECRET-TIME'}, {'SECRET-KEY': 'SECRET-VALUE'}, {'hostname': {'SECRET-NESTED': 1}}):
        try:
            api.parse_canonical_event(data | changed)
        except api.CanonicalReadError as error:
            rendered = ''.join(traceback.format_exception(error))
            assert 'SECRET-' not in str(error)
            assert 'SECRET-' not in rendered
            assert error.field_path in (None, 'timestamp', 'hostname')
        else:
            pytest.fail('invalid data accepted')


def test_upgrade_preserves_all_available_data_and_original(api, data):
    old = CanonicalEvent.model_validate(data | {'technique_ids': ['T1059'], 'src_ip': '192.0.2.1'})
    snapshot = old.model_dump(mode='json')
    new = api.upgrade_canonical_event(old)
    assert type(new) is CanonicalEventV2
    assert new.model_dump(mode='json') == snapshot | {'schema_version': '2.0'}
    assert old.model_dump(mode='json') == snapshot


@pytest.mark.parametrize('field,value', [('schema_version', '2.0'), ('timestamp', 'SECRET-TIME'), ('raw_event_hash', 'bad'), ('src_port', True)])
def test_upgrade_revalidates_untrusted_model_copy(api, data, field, value):
    old = CanonicalEvent.model_validate(data).model_copy(update={field: value})
    with pytest.raises(api.CanonicalReadError):
        api.upgrade_canonical_event(old)


def test_upgrade_rejects_wrong_types_and_unvalidated_construct(api, data):
    for value in (data, CanonicalEventV2.model_validate(data | {'schema_version': '2.0'}), CanonicalEvent.model_construct(**(data | {'timestamp': None}))):
        with pytest.raises(api.CanonicalReadError):
            api.upgrade_canonical_event(value)
