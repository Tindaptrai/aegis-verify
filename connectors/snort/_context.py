"""Explicit caller context; the parser never guesses sensor or deployment facts."""
import re

from aegis_verify.models import PreciseTimestamp
from .errors import SnortParseError


def validate_label(value, field):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value):
        raise SnortParseError('invalid_context', field)


def validate_context(source_ref, environment_id, sensor_id, ingested_at, deployment_mode):
    validate_label(source_ref, 'source_ref')
    validate_label(sensor_id, 'sensor_id')
    try:
        if type(environment_id) is not str or not environment_id.strip() or len(environment_id.encode('utf-8')) > 128:
            raise ValueError
    except (ValueError, UnicodeEncodeError):
        raise SnortParseError('invalid_context', 'environment_id') from None
    if type(deployment_mode) is not str or deployment_mode not in ('ids', 'ips', 'unknown'):
        raise SnortParseError('invalid_context', 'deployment_mode')
    try:
        ingested = PreciseTimestamp.parse(ingested_at)
    except (ValueError, TypeError, OverflowError):
        raise SnortParseError('invalid_context', 'ingested_at') from None
    return dict(source_ref=source_ref, environment_id=environment_id, sensor_id=sensor_id,
                ingested_at=ingested, deployment_mode=deployment_mode)
