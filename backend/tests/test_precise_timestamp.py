from copy import copy, deepcopy
from datetime import datetime, timedelta, timezone, tzinfo
import json

import pytest
from pydantic import TypeAdapter


@pytest.fixture
def timestamp_type():
    from aegis_verify.models.precise_timestamp import PreciseTimestamp
    return PreciseTimestamp


@pytest.mark.parametrize('fraction', ['', '.1', '.12', '.123', '.1234', '.12345', '.123456', '.1234567', '.12345678', '.123456789', '.000000000'])
def test_preserves_every_fraction_width(timestamp_type, fraction):
    text = f'2026-01-02T03:04:05{fraction}Z'
    stamp = timestamp_type.parse(text)
    assert stamp.isoformat() == text
    assert stamp.fractional_digits == max(0, len(fraction) - 1)
    assert timestamp_type.parse(stamp) is stamp


def test_nanosecond_arithmetic_across_epoch(timestamp_type):
    before = timestamp_type.parse('1969-12-31T23:59:59.999999999Z')
    after = timestamp_type.parse('1970-01-01T00:00:00.000000001Z')
    assert before.epoch_nanoseconds == -1
    assert after.epoch_nanoseconds == 1
    assert after.difference_ns(before) == 2
    assert before < after
    assert after > before
    with pytest.raises(ValueError):
        after.to_datetime_exact()


@pytest.mark.parametrize('text,expected', [
    ('2026-01-01T00:00:00.123456789+07:00', '2025-12-31T17:00:00.123456789Z'),
    ('2026-01-01T00:00:00-23:59', '2026-01-01T23:59:00Z'),
    ('0001-01-01T00:00:00Z', '0001-01-01T00:00:00Z'),
    ('9999-12-31T23:59:59.999999999Z', '9999-12-31T23:59:59.999999999Z'),
    ('2024-02-29T00:00:00Z', '2024-02-29T00:00:00Z'),
])
def test_calendar_and_offset(timestamp_type, text, expected):
    assert timestamp_type.parse(text).isoformat() == expected


@pytest.mark.parametrize('value', [None, True, 123, 1.2, b'2026-01-01T00:00:00Z', [], {},
    '2026-01-01T00:00:00.1234567890Z', '2026-01-01T00:00:00.Z',
    '2026-01-01T00:00:00-00:00', '2026-01-01T00:00:00',
    '２０２６-01-01T00:00:00Z', '2026-01-01t00:00:00z',
    ' 2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z\n',
    '2026-01-01T00:00:60Z', '2026-01-01T24:00:00Z',
    '2026-01-01T00:00:00+24:00', '2026-01-01T00:00:00+00:60',
    '2026-02-29T00:00:00Z', '0000-01-01T00:00:00Z',
    '0001-01-01T00:00:00+00:01', '9999-12-31T23:59:59-00:01',
    datetime(2026, 1, 1),
])
def test_rejects_invalid_values(timestamp_type, value):
    with pytest.raises(ValueError):
        timestamp_type.parse(value)


def test_equivalent_instants_hash_and_precision(timestamp_type):
    short = timestamp_type.parse('2026-01-01T01:00:00.1+01:00')
    long = timestamp_type.parse('2026-01-01T00:00:00.100000000Z')
    assert short == long
    assert short <= long and short >= long
    assert hash(short) == hash(long)
    assert short.isoformat() != long.isoformat()
    assert short != '2026-01-01T00:00:00.1Z'
    with pytest.raises(TypeError):
        short < datetime.now(timezone.utc)
    with pytest.raises(TypeError):
        short.difference_ns(1)


def test_exact_datetime_conversion_and_immutability(timestamp_type):
    original = datetime(2026, 1, 1, 7, 0, 0, 123456, tzinfo=timezone(timedelta(hours=7)))
    stamp = timestamp_type.parse(original)
    assert stamp.isoformat() == '2026-01-01T00:00:00.123456Z'
    assert stamp.to_datetime_exact() == original
    assert timestamp_type.parse('2026-01-01T00:00:00.123456000Z').to_datetime_exact() == original
    with pytest.raises((AttributeError, TypeError)):
        stamp.nanosecond = 0
    with pytest.raises(TypeError):
        timestamp_type()
    with pytest.raises(TypeError):
        timestamp_type(0, 1, 0)


def test_pydantic_roundtrip_and_schema(timestamp_type):
    adapter = TypeAdapter(timestamp_type)
    stamp = adapter.validate_json('"2026-01-01T00:00:00.123456789Z"')
    assert adapter.dump_python(stamp) is stamp
    assert json.loads(adapter.dump_json(stamp)) == stamp.isoformat()
    schema = adapter.json_schema()
    assert schema['type'] == 'string'
    assert schema['format'] == 'date-time'
    assert 'pattern' in schema


@pytest.mark.parametrize('parts', [(True, 0, 0), (0, False, 0), (0, 0, True),
    (0, -1, 9), (0, 1_000_000_000, 9), (0, 1, 0), (0, 1, 8),
    (0, 0, -1), (0, 0, 10), (-62135596801, 0, 0), (253402300800, 0, 0)])
def test_internal_factory_cannot_create_invalid_state(timestamp_type, parts):
    with pytest.raises(ValueError):
        timestamp_type._from_parts(*parts)


def test_immutable_value_can_be_copied(timestamp_type):
    stamp = timestamp_type.parse('2026-01-01T00:00:00.000000001Z')
    assert copy(stamp) is stamp
    assert deepcopy(stamp) is stamp


def test_unknown_datetime_offset_rejected(timestamp_type):
    class UnknownOffset(tzinfo):
        def utcoffset(self, dt):
            return None
    with pytest.raises(ValueError):
        timestamp_type.parse(datetime(2026, 1, 1, tzinfo=UnknownOffset()))


@pytest.mark.parametrize('value', [
    datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))),
    datetime(9999, 12, 31, 23, 59, tzinfo=timezone(timedelta(hours=-1))),
])
def test_datetime_utc_overflow_rejected(timestamp_type, value):
    with pytest.raises(ValueError):
        timestamp_type.parse(value)


@pytest.mark.parametrize('field_value', ['1969-12-31T23:59:59.000000001Z',
    '0001-01-01T00:00:00.999999999Z', '9999-12-31T23:59:59.999999999Z'])
def test_exact_integer_and_serialization_at_extreme_dates(timestamp_type, field_value):
    stamp = timestamp_type.parse(field_value)
    adapter = TypeAdapter(timestamp_type)
    assert adapter.validate_json(adapter.dump_json(stamp)) == stamp
    assert timestamp_type.parse(stamp.isoformat()).epoch_nanoseconds == stamp.epoch_nanoseconds
