"""Explicit pfSense fixture context and BSD timestamp conversion."""

import re

from pydantic import ValidationError

from aegis_verify.models import PreciseTimestamp

from .errors import PfSenseParseError
from .models import PfSenseContext


_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}
_BSD_TIMESTAMP = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"([ 0-9][0-9]) ([0-9]{2}):([0-9]{2}):([0-9]{2})$",
    flags=re.ASCII,
)
_CONTEXT_FIELDS = frozenset(PfSenseContext.model_fields)


def make_context(
    *,
    source_ref: object,
    environment_id: object,
    sensor_id: object,
    ingested_at: object,
    source_year: object,
    source_utc_offset: object,
) -> PfSenseContext:
    """Validate caller facts without rewriting valid labels."""

    try:
        return PfSenseContext(
            source_ref=source_ref,
            environment_id=environment_id,
            sensor_id=sensor_id,
            ingested_at=ingested_at,
            source_year=source_year,
            source_utc_offset=source_utc_offset,
        )
    except ValidationError as error:
        location = error.errors(
            include_input=False, include_context=False, include_url=False
        )[0]["loc"]
        field = str(location[0]) if location and location[0] in _CONTEXT_FIELDS else None
        raise PfSenseParseError("invalid_context", field) from None


def source_timestamp(text: str, context: PfSenseContext) -> PreciseTimestamp:
    """Combine a BSD timestamp with explicit caller year/offset and return UTC."""

    if not isinstance(context, PfSenseContext):
        raise PfSenseParseError("invalid_context") from None
    if type(text) is not str:
        raise PfSenseParseError("invalid_timestamp", "timestamp") from None
    match = _BSD_TIMESTAMP.fullmatch(text)
    if match is None:
        raise PfSenseParseError("invalid_timestamp", "timestamp") from None
    month_text, day_text, hour_text, minute_text, second_text = match.groups()
    try:
        wire = (
            f"{context.source_year:04d}-{_MONTHS[month_text]:02d}-"
            f"{int(day_text):02d}T{int(hour_text):02d}:"
            f"{int(minute_text):02d}:{int(second_text):02d}"
            f"{context.source_utc_offset}"
        )
        return PreciseTimestamp.parse(wire)
    except (ValueError, OverflowError):
        raise PfSenseParseError("invalid_timestamp", "timestamp") from None
