"""Version 2 canonical contract with exact UTC nanoseconds."""

from typing import Literal

from ._canonical_fields import CanonicalFields
from .precise_timestamp import PreciseTimestamp


class CanonicalEventV2(CanonicalFields):
    schema_version: Literal['2.0'] = '2.0'
    timestamp: PreciseTimestamp
    ingested_at: PreciseTimestamp
