"""Versioned canonical event contract; source parsing belongs in connectors."""

import re
from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StrictStr,
    field_validator,
)


class SourceType(StrEnum):
    WAZUH = "wazuh"
    SURICATA = "suricata"
    PFSENSE = "pfsense"
    COWRIE = "cowrie"


class EventAction(StrEnum):
    OBSERVED = "observed"
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    REDIRECTED = "redirected"
    LOGIN = "login"
    COMMAND = "command"
    OTHER = "other"


NonBlank = Annotated[StrictStr, Field(min_length=1, pattern=r"\S")]
Port = Annotated[int, Field(strict=True, ge=0, le=65535)]
NonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
RawHash = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})"
)


class CanonicalEvent(BaseModel):
    """Validated source facts, not a detection/prevention conclusion."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    schema_version: Literal["1.0"] = "1.0"
    event_id: NonBlank
    timestamp: AwareDatetime
    source_type: SourceType
    environment_id: NonBlank
    raw_event_ref: NonBlank
    raw_event_hash: RawHash
    ingested_at: AwareDatetime

    source_record_id: StrictStr | None = None
    event_provider: StrictStr | None = None
    asset_id: StrictStr | None = None
    hostname: StrictStr | None = None
    username: StrictStr | None = None
    src_ip: IPvAnyAddress | None = None
    src_port: Port | None = None
    dst_ip: IPvAnyAddress | None = None
    dst_port: Port | None = None
    protocol: StrictStr | None = None
    process_name: StrictStr | None = None
    process_id: NonNegativeInt | None = None
    parent_process_name: StrictStr | None = None
    command_line: StrictStr | None = None
    file_path: StrictStr | None = None
    file_hash: StrictStr | None = None
    rule_id: StrictStr | None = None
    signature_id: StrictStr | None = None
    event_action: EventAction | None = None
    severity: NonNegativeInt | None = None
    technique_ids: tuple[NonBlank, ...] | None = None

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

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def require_address_representation(cls, value: object) -> object:
        """Do not interpret numeric/boolean vendor values as IP addresses."""
        if value is None or isinstance(value, (str, IPv4Address, IPv6Address)):
            return value
        raise ValueError("expected IP address text or an IP address object")

    @field_validator("source_type", "event_action", mode="before")
    @classmethod
    def require_enum_text(cls, value: object) -> object:
        """Keep byte decoding in source parsers, not the domain model."""
        if value is None or isinstance(value, str):
            return value
        raise ValueError("expected a string enum value")

    @field_validator("technique_ids", mode="before")
    @classmethod
    def require_ordered_techniques(cls, value: object) -> object:
        """Prevent nondeterministic iteration of unordered collections."""
        if value is None or isinstance(value, (list, tuple)):
            return value
        raise ValueError("expected a list or tuple of technique identifiers")
