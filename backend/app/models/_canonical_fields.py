"""Versioned canonical event contract; source parsing belongs in connectors."""

from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from pydantic import (
    AfterValidator,
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


def _require_utf8(value: str) -> str:
    """Reject malformed Unicode without rewriting the source text."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("text must be encodable as UTF-8") from None
    return value


Utf8Text = Annotated[StrictStr, AfterValidator(_require_utf8)]
NonBlank = Annotated[StrictStr, Field(min_length=1, pattern=r"\S")]
Port = Annotated[int, Field(strict=True, ge=0, le=65535)]
NonNegativeInt = Annotated[int, Field(strict=True, ge=0)]
RawHash = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]


class CanonicalFields(BaseModel):
    """Validated source facts, not a detection/prevention conclusion."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    event_id: NonBlank
    source_type: SourceType
    environment_id: NonBlank
    raw_event_ref: NonBlank
    raw_event_hash: RawHash

    source_record_id: Utf8Text | None = None
    event_provider: Utf8Text | None = None
    asset_id: Utf8Text | None = None
    hostname: Utf8Text | None = None
    username: Utf8Text | None = None
    src_ip: IPvAnyAddress | None = None
    src_port: Port | None = None
    dst_ip: IPvAnyAddress | None = None
    dst_port: Port | None = None
    protocol: Utf8Text | None = None
    process_name: Utf8Text | None = None
    process_id: NonNegativeInt | None = None
    parent_process_name: Utf8Text | None = None
    command_line: Utf8Text | None = None
    file_path: Utf8Text | None = None
    file_hash: Utf8Text | None = None
    rule_id: Utf8Text | None = None
    signature_id: Utf8Text | None = None
    event_action: EventAction | None = None
    severity: NonNegativeInt | None = None
    technique_ids: tuple[NonBlank, ...] | None = None

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def require_address_representation(cls, value: object) -> object:
        """Do not interpret numeric/boolean vendor values as IP addresses."""
        if value is None or isinstance(value, (str, IPv4Address, IPv6Address)):
            return value
        raise ValueError("expected IP address text or an IP address object")

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def require_serializable_address(
        cls, value: IPv4Address | IPv6Address | None,
    ) -> IPv4Address | IPv6Address | None:
        """IPv6 scope IDs are text even when the input is an IP object."""
        if value is not None:
            _require_utf8(str(value))
        return value

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
