"""Explicit caller context shared by the A and B input adapters."""
import re

from aegis_verify.models import PreciseTimestamp
from .errors import SuricataParseError


def validate_label(value, field):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value):
        raise SuricataParseError('invalid_context', field)


def validate_context(source_ref, environment_id, ingested_at, deployment_mode):
    validate_label(source_ref, 'source_ref')
    try:
        if type(environment_id) is not str or not environment_id.strip() or len(environment_id.encode('utf-8')) > 128:
            raise ValueError
    except (ValueError, UnicodeEncodeError):
        raise SuricataParseError('invalid_context', 'environment_id') from None
    if type(deployment_mode) is not str or deployment_mode not in ('ids', 'ips', 'unknown'):
        raise SuricataParseError('invalid_context', 'deployment_mode')
    try:
        return PreciseTimestamp.parse(ingested_at)
    except (ValueError, TypeError, OverflowError):
        raise SuricataParseError('invalid_context', 'ingested_at') from None
