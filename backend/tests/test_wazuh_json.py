"""Artificial JSON boundary data, not incident evidence."""

import json
import traceback

import pytest


def test_duplicate_keys_are_not_overwritten():
    from aegis_verify.connectors.wazuh._json import decode_document
    from aegis_verify.connectors.wazuh.errors import WazuhParseError
    with pytest.raises(WazuhParseError) as error:
        decode_document(b'{"a":1,"a":2}')
    assert error.value.diagnostic.code == 'duplicate_key'


@pytest.fixture
def boundary():
    from aegis_verify.connectors.wazuh._json import decode_document
    from aegis_verify.connectors.wazuh.errors import WazuhParseError
    return decode_document, WazuhParseError


@pytest.mark.parametrize('raw,want', [
    (b'{}', {}), (b'\xef\xbb\xbf{}\n', {}),
    (b'{"nested": {"text": "[\\\"{}\\\\"}, "number": 1.5}', {'nested': {'text': '["{}\\'}, 'number': 1.5}),
])
def test_valid_json(boundary, raw, want):
    parse, _ = boundary
    assert parse(raw) == want


@pytest.mark.parametrize('raw,code', [
    ('{}', 'input_type'), (None, 'input_type'), (bytearray(b'{}'), 'input_type'),
    (b'\xff', 'invalid_encoding'), (b'\xef\xbb\xbf\xef\xbb\xbf{}', 'invalid_json'),
    (b'[]', 'invalid_root'), (b'null', 'invalid_root'), (b'"x"', 'invalid_root'),
    (b'{}{}', 'invalid_json'), (b'{', 'invalid_json'),
    (b'{"a":1,"\\u0061":2}', 'duplicate_key'),
    (b'{"x":{"a":1,"a":2}}', 'duplicate_key'),
    (b'{"n":NaN}', 'invalid_number'), (b'{"n":Infinity}', 'invalid_number'),
    (b'{"n":-Infinity}', 'invalid_number'), (b'{"n":1e999}', 'invalid_number'),
    (b'{"n":' + b'1' * 129 + b'}', 'invalid_number'),
    (b'{"n":1e' + b'1' * 127 + b'}', 'invalid_number'),
    (b'{"unknown":"\\ud800"}', 'invalid_unicode'),
    (b'{"\\udfff":0}', 'invalid_unicode'),
])
def test_rejects_bad_json(boundary, raw, code):
    parse, error = boundary
    with pytest.raises(error) as caught:
        parse(raw)
    assert caught.value.diagnostic.code == code
    assert caught.value.diagnostic.record_index == 1


def test_byte_limit(boundary):
    parse, error = boundary
    at_limit = b'{}' + b' ' * (256 * 1024 - 2)
    assert parse(at_limit) == {}
    with pytest.raises(error) as caught:
        parse(at_limit + b' ')
    assert caught.value.diagnostic.code == 'input_too_large'


def test_container_depth_boundary(boundary):
    parse, error = boundary
    accepted = b'{"x":' + b'[' * 19 + b'0' + b']' * 19 + b'}'
    assert parse(accepted)['x'] is not None
    with pytest.raises(error) as caught:
        parse(b'{"x":' + b'[' * 20 + b'0' + b']' * 20 + b'}')
    assert caught.value.diagnostic.code == 'max_depth'
    assert parse(json.dumps({'x': '[' * 100 + '\\"' + '}' * 100}).encode())['x'].startswith('[')


def test_node_limit(boundary):
    parse, error = boundary
    assert len(parse(json.dumps({'x': [0] * 9998}).encode())['x']) == 9998
    with pytest.raises(error) as caught:
        parse(json.dumps({'x': [0] * 9999}).encode())
    assert caught.value.diagnostic.code == 'max_nodes'


def test_numeric_boundary(boundary):
    parse, _ = boundary
    assert parse(b'{"n":' + b'1' * 128 + b'}')['n'] == int('1' * 128)


def test_public_errors_are_safe_and_immutable(boundary):
    parse, error = boundary
    raw = b'{"SECRET-MARKER": "SECRET-VALUE",}'
    with pytest.raises(error) as caught:
        parse(raw)
    diagnostic = caught.value.diagnostic
    assert diagnostic.line == 1
    assert isinstance(diagnostic.column, int)
    assert diagnostic.field_path is None
    assert 'SECRET' not in ''.join(traceback.format_exception(caught.value))
    with pytest.raises((AttributeError, TypeError)):
        diagnostic.code = 'other'
