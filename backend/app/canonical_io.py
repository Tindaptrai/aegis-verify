"""Bounded canonical JSON boundary; no source parsing or implicit migration."""

import json
import math

from pydantic import ValidationError
from pydantic_core import PydanticSerializationError

from .models import CanonicalEvent, CanonicalEventV2

MAX_INPUT_BYTES = 1024 * 1024
MAX_CONTAINER_DEPTH = 32
MAX_NUMERIC_CHARS = 128
_MODELS = {'1.0': CanonicalEvent, '2.0': CanonicalEventV2}
_FIELDS = frozenset(CanonicalEvent.model_fields)
_CODES = frozenset({
    'invalid_json', 'input_too_large', 'input_too_deep', 'invalid_number',
    'unsupported_version', 'invalid_event', 'invalid_upgrade',
})


class CanonicalReadError(ValueError):
    """Safe public diagnostics. Never carries source values or unknown field names."""

    def __init__(self, code: str, field_path: str | None = None):
        self.code = code if code in _CODES else 'invalid_event'
        self.field_path = field_path if field_path in _FIELDS else None
        super().__init__(self.code + (f': {self.field_path}' if self.field_path else ''))


def _number(token: str):
    if len(token) > MAX_NUMERIC_CHARS:
        raise CanonicalReadError('invalid_number')
    if '.' not in token and 'e' not in token.lower():
        return int(token)
    value = float(token)
    if not math.isfinite(value):
        raise CanonicalReadError('invalid_number')
    return value


def _constant(token):
    raise CanonicalReadError('invalid_number')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalReadError('invalid_json')
        result[key] = value
    return result


def _preflight_depth(text: str):
    """Guard nesting before json.loads; braces in escaped strings are data."""
    depth, in_string, escaped = 0, False, False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in '[{':
            depth += 1
            if depth > MAX_CONTAINER_DEPTH:
                raise CanonicalReadError('input_too_deep')
        elif char in ']}':
            depth -= 1


def _check_tree(data):
    """Validate JSON-only dict input with a bounded expanded UTF-8 JSON budget.

    Count repeated subtrees each time: shared references must not allow an
    exponentially expanded payload to bypass the size budget. Active-path IDs
    distinguish cycles from harmless shared references.
    """
    remaining = MAX_INPUT_BYTES
    active = set()

    def charge(amount):
        nonlocal remaining
        remaining -= amount
        if remaining < 0:
            raise CanonicalReadError('input_too_large')

    def string_cost(value):
        if len(value) > MAX_INPUT_BYTES:
            raise CanonicalReadError('input_too_large')
        try:
            charge(len(json.dumps(value, ensure_ascii=False).encode('utf-8')))
        except UnicodeEncodeError:
            raise CanonicalReadError('invalid_json') from None

    def walk(value, depth):
        kind = type(value)
        if kind is str:
            string_cost(value)
        elif value is None or kind is bool:
            charge(5 if value is False else 4)
        elif kind is int:
            if abs(value) >= 10 ** MAX_NUMERIC_CHARS or len(str(value)) > MAX_NUMERIC_CHARS:
                raise CanonicalReadError('invalid_number')
            charge(len(str(value)))
        elif kind is float:
            if not math.isfinite(value):
                raise CanonicalReadError('invalid_number')
            charge(len(repr(value)))
        elif kind in (dict, list):
            if depth >= MAX_CONTAINER_DEPTH:
                raise CanonicalReadError('input_too_deep')
            identity = id(value)
            if identity in active:
                raise CanonicalReadError('invalid_json')
            active.add(identity)
            charge(2 + max(0, len(value) - 1))  # delimiters and commas
            try:
                if kind is dict:
                    for key, item in value.items():
                        if type(key) is not str:
                            raise CanonicalReadError('invalid_json')
                        string_cost(key)
                        charge(1)  # colon
                        walk(item, depth + 1)
                else:
                    for item in value:
                        walk(item, depth + 1)
            finally:
                active.remove(identity)
        else:
            raise CanonicalReadError('invalid_json')

    if type(data) is not dict:
        raise CanonicalReadError('invalid_json')
    walk(data, 0)


def _validation_error(error: ValidationError, code='invalid_event'):
    # No input/context/url; nested locations and unknown keys are never exposed.
    locations = error.errors(include_input=False, include_context=False, include_url=False)
    first = locations[0]['loc'] if locations else ()
    field = first[0] if first and first[0] in _FIELDS else None
    return CanonicalReadError(code, field)


def parse_canonical_event(data: dict) -> CanonicalEvent | CanonicalEventV2:
    """Read an explicitly versioned JSON-like dict without mutating it."""
    _check_tree(data)
    version = data.get('schema_version')
    if type(version) is not str or version not in _MODELS:
        raise CanonicalReadError('unsupported_version', 'schema_version')
    try:
        return _MODELS[version].model_validate(data)
    except ValidationError as error:
        raise _validation_error(error) from None


def parse_canonical_event_json(raw: str | bytes) -> CanonicalEvent | CanonicalEventV2:
    """Read strict UTF-8 JSON, rejecting duplicates, nonfinite numbers and excess."""
    if type(raw) not in (str, bytes):
        raise CanonicalReadError('invalid_json')
    if len(raw) > MAX_INPUT_BYTES:
        raise CanonicalReadError('input_too_large')
    try:
        if isinstance(raw, bytes):
            text = raw.decode('utf-8')
        else:
            if len(raw.encode('utf-8')) > MAX_INPUT_BYTES:
                raise CanonicalReadError('input_too_large')
            text = raw
        _preflight_depth(text)
        data = json.loads(text, object_pairs_hook=_object, parse_int=_number,
                          parse_float=_number, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise CanonicalReadError('invalid_json') from None
    return parse_canonical_event(data)


def upgrade_canonical_event(event: CanonicalEvent) -> CanonicalEventV2:
    """Explicit v1 -> v2 migration; cannot recover digits already lost in v1."""
    if type(event) is not CanonicalEvent:
        raise CanonicalReadError('invalid_upgrade')
    try:
        # Inspect fields directly to avoid invoking serializers on a forged
        # model_copy/model_construct. Revalidation must precede serialization.
        values = dict(event.__dict__)
        if event.__pydantic_extra__:
            values.update(event.__pydantic_extra__)
        validated = CanonicalEvent.model_validate(values)
        data = validated.model_dump(mode='json', warnings=False)
        data['schema_version'] = '2.0'
        # Migration is model-to-model, not a wire reader: preserve all valid
        # model values, including values beyond the reader's resource policy.
        return CanonicalEventV2.model_validate(data)
    except ValidationError as error:
        raise _validation_error(error, 'invalid_upgrade') from None
    except (PydanticSerializationError, UnicodeError, OverflowError, ValueError):
        raise CanonicalReadError('invalid_upgrade') from None
