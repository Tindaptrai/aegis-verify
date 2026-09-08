"""Version 1 contract: compatibility API with microsecond datetime precision."""

import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import AwareDatetime, field_validator

from ._canonical_fields import CanonicalFields, EventAction, SourceType

RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})"
)


class CanonicalEvent(CanonicalFields):
    schema_version: Literal["1.0"] = "1.0"
    timestamp: AwareDatetime
    ingested_at: AwareDatetime

    @field_validator("timestamp", "ingested_at", mode="before")
    @classmethod
    def require_explicit_time(cls, value: object) -> object:
        """Reject epoch guessing, absent offsets and silent precision loss."""
        if isinstance(value, datetime):
            return value
        if (
            isinstance(value, str)
            and RFC3339.fullmatch(value)
            and not value.endswith("-00:00")
        ):
            return value
        raise ValueError(
            "expected aware datetime or RFC 3339 with a known offset "
            "and at most 6 fractional digits"
        )

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def normalize_utc(cls, value: datetime) -> datetime:
        """Keep the instant; the original timestamp remains in raw evidence."""
        try:
            return value.astimezone(timezone.utc)
        except (OverflowError, ValueError) as exc:
            raise ValueError("timestamp is outside the representable UTC range") from exc
