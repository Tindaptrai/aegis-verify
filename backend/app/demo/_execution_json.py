"""Bounded runner JSON; Decimal allowed only at top-level elapsed_seconds."""

from decimal import Decimal, InvalidOperation
import json

from ..intake.io import (MAX_CONFIG_BYTES, MAX_INTEGER_CHARS, unique_object, _integer,
                         _unsupported_number, _preflight_depth, _validate_tree)
from ._study_contracts import StudyRunError


def _decimal(token):
    if len(token) > MAX_INTEGER_CHARS:
        raise StudyRunError()
    try:
        number = Decimal(token)
    except InvalidOperation:
        raise StudyRunError() from None
    if not number.is_finite():
        raise StudyRunError()
    return number


def decode_execution(raw):
    if type(raw) is not bytes or len(raw) > MAX_CONFIG_BYTES:
        raise StudyRunError()
    text = raw.decode('utf-8-sig')
    _preflight_depth(text, stage='inputs')
    result = json.loads(text, object_pairs_hook=unique_object, parse_int=_integer,
                        parse_float=_decimal, parse_constant=_unsupported_number)
    if type(result) is not dict:
        raise StudyRunError()
    _validate_tree(result, stage='inputs')
    for key, value in result.items():
        if isinstance(value, (list, dict)) or (type(value) is Decimal and key != 'elapsed_seconds'):
            raise StudyRunError()
    return result
