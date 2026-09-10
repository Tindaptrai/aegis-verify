"""Immutable Cowrie parser result and provenance contracts."""

import re
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictStr, model_validator

from aegis_verify.models import CanonicalEventV2, PreciseTimestamp

from ._context import evidence_id, session_key


SOURCE_KINDS = (
    "cowrie.session.params",
    "cowrie.session.connect",
    "cowrie.session.closed",
    "cowrie.login.success",
    "cowrie.login.failed",
    "cowrie.command.input",
)
SourceKind = Literal[
    "cowrie.session.params",
    "cowrie.session.connect",
    "cowrie.session.closed",
    "cowrie.login.success",
    "cowrie.login.failed",
    "cowrie.command.input",
]
_SAFE_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", re.ASCII)
_HEX_64 = re.compile(r"[0-9a-f]{64}", re.ASCII)


def _valid_label(value: str) -> str:
    if _SAFE_LABEL.fullmatch(value) is None:
        raise ValueError("invalid safe label")
    return value


def _valid_environment(value: str) -> str:
    try:
        if not value.strip() or len(value.encode("utf-8")) > 128:
            raise ValueError
    except UnicodeEncodeError:
        raise ValueError("invalid environment label") from None
    return value


def _valid_utf8(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("invalid UTF-8 text") from None
    return value


def _valid_hash(value: str) -> str:
    if _HEX_64.fullmatch(value) is None:
        raise ValueError("invalid raw hash")
    return value


SafeLabel = Annotated[StrictStr, AfterValidator(_valid_label)]
EnvironmentId = Annotated[StrictStr, AfterValidator(_valid_environment)]
Utf8Text = Annotated[StrictStr, AfterValidator(_valid_utf8)]
RawHash = Annotated[StrictStr, AfterValidator(_valid_hash)]
PositiveInt = Annotated[int, Field(strict=True, gt=0)]
FractionDigits = Annotated[int, Field(strict=True, ge=0, le=9)]
RuleLevel = Annotated[int, Field(strict=True, ge=0)]


class CowrieProvenance(BaseModel):
    """Source-specific evidence metadata; never a security verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, hide_input_in_errors=True)

    mapping_version: Literal["cowrie-wazuh-v1"] = "cowrie-wazuh-v1"
    input_profile: Literal["wazuh-cowrie-v1"] = "wazuh-cowrie-v1"
    payload_basis: Literal["wazuh._source.data"] = "wazuh._source.data"
    timestamp_basis: Literal["cowrie.data.timestamp"] = "cowrie.data.timestamp"
    source_record_namespace: Literal["wazuh.alert.id"] = "wazuh.alert.id"
    environment_id: EnvironmentId
    sensor_id: SafeLabel
    source_ref: SafeLabel
    record_index: Literal[1] = 1
    line_start: Literal[1] = 1
    line_end: PositiveInt
    event_id: Utf8Text
    raw_event_hash: RawHash
    raw_event_ref: Utf8Text
    source_event_type: SourceKind
    session: Utf8Text | None = None
    session_key: Utf8Text | None = None
    source_sensor: Utf8Text | None = None
    source_uuid: Utf8Text | None = None
    arch: Utf8Text | None = None
    source_fraction_digits: FractionDigits
    authentication_outcome: Literal["success", "failure"] | None = None
    wazuh_timestamp: PreciseTimestamp | None = None
    wazuh_rule_id: Utf8Text | None = None
    wazuh_rule_level: RuleLevel | None = None
    collector_agent_id: Utf8Text | None = None
    collector_agent_name: Utf8Text | None = None
    collector_agent_ip: Utf8Text | None = None
    collector_manager_name: Utf8Text | None = None

    @model_validator(mode="after")
    def require_valid_relationships(self) -> Self:
        expected_outcome = {
            "cowrie.login.success": "success",
            "cowrie.login.failed": "failure",
        }.get(self.source_event_type)
        if self.authentication_outcome != expected_outcome:
            raise ValueError("source kind and authentication outcome disagree")
        if self.raw_event_ref != f"{self.source_ref}#L1-L{self.line_end}":
            raise ValueError("raw reference and line range disagree")
        if self.event_id != evidence_id(
            self.environment_id, self.sensor_id, self.source_ref, self.raw_event_hash
        ):
            raise ValueError("event identity does not match provenance")
        if self.session is None:
            if self.session_key is not None:
                raise ValueError("session key requires source session")
        elif (
            not self.session.strip()
            or self.session_key
            != session_key(self.environment_id, self.sensor_id, self.session)
        ):
            raise ValueError("session and session key disagree")
        return self


class CowrieParseResult(BaseModel):
    """One canonical Cowrie event paired with its immutable provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, hide_input_in_errors=True)

    event: CanonicalEventV2
    provenance: CowrieProvenance

    @model_validator(mode="after")
    def require_consistent_result(self) -> Self:
        event, provenance = self.event, self.provenance
        expected_action = {
            "cowrie.session.params": "observed",
            "cowrie.session.connect": "observed",
            "cowrie.session.closed": "observed",
            "cowrie.login.success": "login",
            "cowrie.login.failed": "login",
            "cowrie.command.input": "command",
        }[provenance.source_event_type]
        if event.source_type != "cowrie" or event.event_provider != "cowrie":
            raise ValueError("result is not a Cowrie canonical event")
        if event.event_action != expected_action:
            raise ValueError("source kind and canonical action disagree")
        if (
            event.event_id != provenance.event_id
            or event.raw_event_hash != provenance.raw_event_hash
            or event.raw_event_ref != provenance.raw_event_ref
            or event.environment_id != provenance.environment_id
        ):
            raise ValueError("event evidence identity does not match provenance")
        if event.timestamp.fractional_digits != provenance.source_fraction_digits:
            raise ValueError("timestamp precision does not match provenance")
        return self
