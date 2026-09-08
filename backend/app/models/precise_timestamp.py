"""Exact UTC instants. Fractional width is representation, not clock accuracy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import total_ordering
import re

from pydantic_core import core_schema


# Calendar validity and UTC range are checked separately. ASCII digits only.
TIMESTAMP_PATTERN = (
    r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
    r'(?:\.[0-9]{1,9})?(?:Z|\+[0-9]{2}:[0-9]{2}|-(?!00:00)[0-9]{2}:[0-9]{2})$'
)
_TEXT = re.compile(TIMESTAMP_PATTERN)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MIN_SECONDS = -62135596800
_MAX_SECONDS = 253402300799


@total_ordering
class PreciseTimestamp:
    """Immutable integer-backed value; construct through parse(), not components."""

    __slots__ = ('_seconds', '_nanos', '_digits')

    def __setattr__(self, name, value):
        raise AttributeError('PreciseTimestamp is immutable')

    def __delattr__(self, name):
        raise AttributeError('PreciseTimestamp is immutable')

    def __init__(self):
        raise TypeError('use PreciseTimestamp.parse')

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        # Sharing is safe for an immutable value, including model_copy(deep=True).
        return self

    @classmethod
    def _from_parts(cls, seconds: int, nanos: int, digits: int):
        if (
            any(type(value) is not int for value in (seconds, nanos, digits))
            or not _MIN_SECONDS <= seconds <= _MAX_SECONDS
            or not 0 <= nanos < 1_000_000_000
            or not 0 <= digits <= 9
            or nanos % (10 ** (9 - digits)) != 0
        ):
            raise ValueError('invalid timestamp components')
        value = object.__new__(cls)
        object.__setattr__(value, '_seconds', seconds)
        object.__setattr__(value, '_nanos', nanos)
        object.__setattr__(value, '_digits', digits)
        return value

    @classmethod
    def parse(cls, value: str | datetime | 'PreciseTimestamp') -> 'PreciseTimestamp':
        if isinstance(value, cls):
            return value
        try:
            if isinstance(value, datetime):
                if value.tzinfo is None or value.utcoffset() is None:
                    raise ValueError
                utc = value.astimezone(timezone.utc)
                nanos, digits = utc.microsecond * 1000, 6
                whole = utc.replace(microsecond=0)
            elif isinstance(value, str) and len(value) <= 35 and _TEXT.fullmatch(value):
                whole = datetime.fromisoformat(value[:19]).replace(tzinfo=timezone.utc)
                zone_start = len(value) - (1 if value.endswith('Z') else 6)
                fraction = value[20:zone_start] if value[19:20] == '.' else ''
                digits = len(fraction)
                nanos = int(fraction.ljust(9, '0')) if fraction else 0
                if not value.endswith('Z'):
                    zone = value[-6:]
                    hours, minutes = int(zone[1:3]), int(zone[4:6])
                    if hours > 23 or minutes > 59:
                        raise ValueError
                    sign = 1 if zone[0] == '+' else -1
                    whole -= timedelta(minutes=sign * (hours * 60 + minutes))
            else:
                raise ValueError
            delta = whole - _EPOCH
            return cls._from_parts(delta.days * 86400 + delta.seconds, nanos, digits)
        except (ValueError, OverflowError):
            raise ValueError('expected an in-range timestamp with known offset and 0..9 fractional digits') from None

    @property
    def nanosecond(self) -> int:
        return self._nanos

    @property
    def fractional_digits(self) -> int:
        return self._digits

    @property
    def epoch_nanoseconds(self) -> int:
        return self._seconds * 1_000_000_000 + self._nanos

    def isoformat(self) -> str:
        whole = _EPOCH + timedelta(seconds=self._seconds)
        text = (f'{whole.year:04d}-{whole.month:02d}-{whole.day:02d}'
                f'T{whole.hour:02d}:{whole.minute:02d}:{whole.second:02d}')
        if self._digits:
            text += '.' + f'{self._nanos:09d}'[:self._digits]
        return text + 'Z'

    def to_datetime_exact(self) -> datetime:
        """Never round or truncate sub-microsecond data."""
        if self._nanos % 1000:
            raise ValueError('timestamp cannot be represented exactly as datetime')
        return _EPOCH + timedelta(seconds=self._seconds, microseconds=self._nanos // 1000)

    def difference_ns(self, other: 'PreciseTimestamp') -> int:
        if not isinstance(other, PreciseTimestamp):
            raise TypeError('expected PreciseTimestamp')
        return self.epoch_nanoseconds - other.epoch_nanoseconds

    def __eq__(self, other):
        if not isinstance(other, PreciseTimestamp):
            return NotImplemented
        return self.epoch_nanoseconds == other.epoch_nanoseconds

    def __lt__(self, other):
        if not isinstance(other, PreciseTimestamp):
            return NotImplemented
        return self.epoch_nanoseconds < other.epoch_nanoseconds

    def __hash__(self):
        return hash(self.epoch_nanoseconds)

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        return core_schema.no_info_plain_validator_function(
            cls.parse,
            json_schema_input_schema=core_schema.str_schema(),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda value: value.isoformat(), when_used='json',
                return_schema=core_schema.str_schema(),
            ),
        )

    @classmethod
    def __get_pydantic_json_schema__(cls, schema, handler):
        return {'type': 'string', 'format': 'date-time', 'pattern': TIMESTAMP_PATTERN}
