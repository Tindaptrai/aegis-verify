"""Strict optional source fields; absence is not an inferred default."""
from ipaddress import ip_address
import re

from .errors import SuricataParseError


def text(value, path):
    if value is None:
        return None
    if type(value) is not str:
        raise SuricataParseError('invalid_field', path)
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise SuricataParseError('invalid_field', path) from None
    return value


def decimal_id(value, path):
    if value is None:
        return None
    if type(value) is int and 0 <= value < 10**128:
        return str(value)
    if type(value) is str and re.fullmatch(r'[0-9]{1,128}', value):
        return value
    raise SuricataParseError('invalid_field', path)


def number(value, path, *, maximum=None):
    token = decimal_id(value, path)
    if token is None:
        return None
    result = int(token)
    if maximum is not None and result > maximum:
        raise SuricataParseError('invalid_field', path)
    return result


def address(value, path):
    value = text(value, path)
    if value is None:
        return None
    try:
        if '%' in value:
            raise ValueError
        return ip_address(value)
    except ValueError:
        raise SuricataParseError('invalid_field', path) from None


def flow_id(value, path):
    if value is None or type(value) is int:
        return decimal_id(value, path)
    if type(value) is str and len(value) <= 128 and re.fullmatch(r'[0-9]+(?:\.0{1,9})?', value):
        return value
    raise SuricataParseError('invalid_field', path)


def object_field(value, path, *, optional=False):
    if value is None and optional:
        return {}
    if type(value) is not dict:
        raise SuricataParseError('invalid_field', path)
    return value
