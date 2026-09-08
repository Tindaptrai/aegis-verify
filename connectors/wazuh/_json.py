"""Bounded decoder for one Wazuh document, independent of canonical wire policy."""

import json
import math

from .errors import WazuhParseError

MAX_BYTES = 256 * 1024
MAX_DEPTH = 20
MAX_NODES = 10_000
MAX_NUMERIC_CHARS = 128


def _preflight(text):
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > MAX_DEPTH:
                raise WazuhParseError('max_depth')
        elif char in ']}':
            depth -= 1


def _number(token):
    if len(token) > MAX_NUMERIC_CHARS:
        raise WazuhParseError('invalid_number')
    if '.' not in token and 'e' not in token.lower():
        return int(token)
    result = float(token)
    if not math.isfinite(result):
        raise WazuhParseError('invalid_number')
    return result


def _constant(token):
    raise WazuhParseError('invalid_number')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WazuhParseError('duplicate_key')
        result[key] = value
    return result


def _tree(data):
    stack, nodes = [data], 0
    while stack:
        value = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise WazuhParseError('max_nodes')
        if isinstance(value, dict):
            for key in value:
                key.encode('utf-8')
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
        elif isinstance(value, str):
            value.encode('utf-8')


def decode_document(raw: bytes) -> dict:
    if type(raw) is not bytes:
        raise WazuhParseError('input_type')
    if len(raw) > MAX_BYTES:
        raise WazuhParseError('input_too_large')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise WazuhParseError('invalid_encoding') from None
    _preflight(text)
    try:
        data = json.loads(text, object_pairs_hook=_pairs, parse_int=_number,
                          parse_float=_number, parse_constant=_constant)
    except json.JSONDecodeError as error:
        raise WazuhParseError('invalid_json', line=error.lineno, column=error.colno) from None
    except RecursionError:
        raise WazuhParseError('max_depth') from None
    if type(data) is not dict:
        raise WazuhParseError('invalid_root')
    try:
        _tree(data)
    except UnicodeEncodeError:
        raise WazuhParseError('invalid_unicode') from None
    return data
