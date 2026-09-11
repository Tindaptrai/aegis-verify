"""Immutable outcomes and provenance for native Cowrie JSONL evidence."""

import re
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, model_validator

from aegis_verify.models import CanonicalEventV2

from ._context import native_evidence_id, session_key
from .models import (
    EnvironmentId,
    FractionDigits,
    PositiveInt,
    RawHash,
    SOURCE_KINDS,
    SafeLabel,
    Utf8Text,
)


_EVENT_KIND = re.compile(
    r"cowrie\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", re.ASCII
)
_ACTIONS = {
    "cowrie.session.params": "observed",
    "cowrie.session.connect": "observed",
    "cowrie.session.closed": "observed",
    "cowrie.login.success": "login",
    "cowrie.login.failed": "login",
    "cowrie.command.input": "command",
}


class CowrieNativeProvenance(BaseModel):
    """Native source facts and evidence identity; never a security verdict."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, hide_input_in_errors=True
    )

    mapping_version: Literal["cowrie-native-v1"] = "cowrie-native-v1"
    input_profile: Literal["cowrie-jsonl-v1"] = "cowrie-jsonl-v1"
    payload_basis: Literal["cowrie.native"] = "cowrie.native"
    timestamp_basis: Literal["cowrie.timestamp"] | None = None
    environment_id: EnvironmentId
    sensor_id: SafeLabel
    source_ref: SafeLabel
    record_index: PositiveInt
    line_start: PositiveInt
    line_end: PositiveInt
    event_id: Utf8Text
    raw_event_hash: RawHash
    raw_event_ref: Utf8Text
    source_event_type: Utf8Text | None = None
    session: Utf8Text | None = None
    session_key: Utf8Text | None = None
    source_sensor: Utf8Text | None = None
    source_uuid: Utf8Text | None = None
    arch: Utf8Text | None = None
    source_fraction_digits: FractionDigits | None = None
    authentication_outcome: Literal["success", "failure"] | None = None

    @model_validator(mode="after")
    def require_valid_relationships(self) -> Self:
        index = self.record_index
        if self.line_start != index or self.line_end != index:
            raise ValueError("native coordinates disagree")
        if self.raw_event_ref != f"{self.source_ref}#L{index}-L{index}":
            raise ValueError("raw reference and coordinates disagree")
        if self.event_id != native_evidence_id(
            self.environment_id,
            self.sensor_id,
            self.source_ref,
            index,
            self.raw_event_hash,
        ):
            raise ValueError("event identity does not match provenance")
        if self.source_event_type is not None and (
            len(self.source_event_type) > 128
            or _EVENT_KIND.fullmatch(self.source_event_type) is None
        ):
            raise ValueError("invalid source event type")
        if self.session is None:
            if self.session_key is not None:
                raise ValueError("session key requires source session")
        elif (
            not self.session.strip()
            or self.session_key
            != session_key(self.environment_id, self.sensor_id, self.session)
        ):
            raise ValueError("session and session key disagree")
        expected_outcome = {
            "cowrie.login.success": "success",
            "cowrie.login.failed": "failure",
        }.get(self.source_event_type)
        if self.authentication_outcome != expected_outcome:
            raise ValueError("source kind and authentication outcome disagree")
        if self.source_event_type in SOURCE_KINDS:
            if self.timestamp_basis != "cowrie.timestamp":
                raise ValueError("supported source kind requires timestamp provenance")
            if self.source_fraction_digits is None:
                raise ValueError("supported source kind requires source precision")
        elif self.timestamp_basis is not None or self.source_fraction_digits is not None:
            raise ValueError("unmapped source kind cannot claim timestamp provenance")
        return self


class CowrieNativeRecord(BaseModel):
    """One explicit parsed or skipped physical-line outcome."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, hide_input_in_errors=True
    )

    status: Literal["parsed", "skipped"]
    reason: Literal["blank_line", "unsupported_event_type"] | None = None
    event: CanonicalEventV2 | None = None
    provenance: CowrieNativeProvenance

    @model_validator(mode="after")
    def require_consistent_outcome(self) -> Self:
        event, provenance = self.event, self.provenance
        if self.status == "parsed":
            if self.reason is not None or event is None:
                raise ValueError("parsed outcome requires only an event")
            if provenance.source_event_type not in SOURCE_KINDS:
                raise ValueError("parsed outcome requires a supported source kind")
            if provenance.timestamp_basis != "cowrie.timestamp":
                raise ValueError("parsed outcome requires timestamp provenance")
            if provenance.source_fraction_digits is None:
                raise ValueError("parsed outcome requires source precision")
            if event.source_type != "cowrie" or event.event_provider != "cowrie":
                raise ValueError("result is not a Cowrie canonical event")
            if event.event_action != _ACTIONS[provenance.source_event_type]:
                raise ValueError("source kind and canonical action disagree")
            if event.source_record_id is not None:
                raise ValueError("native source record identity must remain null")
            if (
                event.event_id != provenance.event_id
                or event.raw_event_hash != provenance.raw_event_hash
                or event.raw_event_ref != provenance.raw_event_ref
                or event.environment_id != provenance.environment_id
            ):
                raise ValueError("event evidence identity does not match provenance")
            if event.timestamp.fractional_digits != provenance.source_fraction_digits:
                raise ValueError("timestamp precision does not match provenance")
        else:
            if self.reason is None or event is not None:
                raise ValueError("skipped outcome requires only a reason")
            if provenance.timestamp_basis is not None:
                raise ValueError("skipped outcome cannot claim timestamp provenance")
            if provenance.source_fraction_digits is not None:
                raise ValueError("skipped outcome cannot claim source precision")
            if self.reason == "blank_line" and provenance.source_event_type is not None:
                raise ValueError("blank outcome cannot claim a source kind")
            if self.reason == "unsupported_event_type" and (
                provenance.source_event_type is None
                or provenance.source_event_type in SOURCE_KINDS
            ):
                raise ValueError("unsupported outcome requires an unsupported kind")
            if provenance.session is not None or provenance.session_key is not None:
                raise ValueError("skipped outcome cannot claim mapped session facts")
            if provenance.source_sensor is not None or provenance.source_uuid is not None:
                raise ValueError("skipped outcome cannot claim mapped source facts")
            if provenance.arch is not None or provenance.authentication_outcome is not None:
                raise ValueError("skipped outcome cannot claim mapped source facts")
        return self
