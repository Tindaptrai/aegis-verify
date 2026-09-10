"""Immutable pfSense caller context, provenance, and line outcomes."""

from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    model_validator,
)

from aegis_verify.models import CanonicalEventV2, PreciseTimestamp


def _valid_environment(value: str) -> str:
    try:
        if not value.strip() or len(value.encode("utf-8")) > 128:
            raise ValueError
    except UnicodeEncodeError:
        raise ValueError("invalid environment label") from None
    return value


def _valid_offset(value: str) -> str:
    if (
        len(value) != 6
        or value[0] not in "+-"
        or value[3] != ":"
        or not value[1:3].isascii()
        or not value[4:6].isascii()
        or not value[1:3].isdigit()
        or not value[4:6].isdigit()
        or int(value[1:3]) > 23
        or int(value[4:6]) > 59
        or value == "-00:00"
    ):
        raise ValueError("invalid UTC offset")
    return value


SafeLabel = Annotated[
    StrictStr, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
]
EnvironmentId = Annotated[StrictStr, AfterValidator(_valid_environment)]
SourceYear = Annotated[int, Field(strict=True, ge=1, le=9999)]
SourceUtcOffset = Annotated[StrictStr, AfterValidator(_valid_offset)]
PositiveInt = Annotated[int, Field(strict=True, gt=0)]
RawHash = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
NonBlank = Annotated[StrictStr, Field(min_length=1, pattern=r"\S")]


class PfSenseContext(BaseModel):
    """Caller-supplied facts required to interpret a BSD syslog fixture."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, hide_input_in_errors=True
    )

    source_ref: SafeLabel
    environment_id: EnvironmentId
    sensor_id: SafeLabel
    ingested_at: PreciseTimestamp
    source_year: SourceYear
    source_utc_offset: SourceUtcOffset


class PfSenseProvenance(BaseModel):
    """Auditable source metadata; this is not a prevention verdict."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, hide_input_in_errors=True
    )

    mapping_version: Literal["pfsense-filterlog-v1"] = "pfsense-filterlog-v1"
    input_profile: Literal[
        "pfsense-filterlog-bsd-ipv4-tcp-udp-v1"
    ] = "pfsense-filterlog-bsd-ipv4-tcp-udp-v1"
    timestamp_basis: Literal["bsd_syslog_with_caller_context"] | None = None
    source_ref: SafeLabel
    sensor_id: SafeLabel
    record_index: PositiveInt
    line_start: PositiveInt
    line_end: PositiveInt
    event_id: NonBlank | None = None
    raw_event_hash: RawHash
    raw_event_ref: NonBlank
    interface: StrictStr | None = None
    direction: StrictStr | None = None
    reason: StrictStr | None = None
    rule_number: StrictStr | None = None
    subrule: StrictStr | None = None
    anchor: StrictStr | None = None
    tracker: StrictStr | None = None
    protocol_id: StrictStr | None = None
    protocol_text: StrictStr | None = None
    timestamp_text: StrictStr | None = None
    source_year: SourceYear
    source_utc_offset: SourceUtcOffset
    nat_context: None = None
    warnings: tuple[
        Literal["year_and_offset_supplied_by_caller"], ...
    ] = ()


class PfSenseRecord(BaseModel):
    """One explicit parsed or skipped physical-line outcome."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, hide_input_in_errors=True
    )

    status: Literal["parsed", "skipped"]
    reason: Literal[
        "blank_line",
        "rotation_notice",
        "unsupported_ip_version",
        "unsupported_protocol",
    ] | None = None
    event: CanonicalEventV2 | None = None
    provenance: PfSenseProvenance

    @model_validator(mode="after")
    def require_consistent_outcome(self) -> Self:
        if self.status == "parsed":
            if self.reason is not None or self.event is None:
                raise ValueError("parsed outcome requires an event and no skip reason")
            if (
                self.provenance.event_id != self.event.event_id
                or self.provenance.raw_event_hash != self.event.raw_event_hash
                or self.provenance.raw_event_ref != self.event.raw_event_ref
            ):
                raise ValueError("parsed evidence identity does not match provenance")
        elif (
            self.reason is None
            or self.event is not None
            or self.provenance.event_id is not None
        ):
            raise ValueError(
                "skipped outcome requires a reason and no event identity"
            )
        return self
