"""Closed contracts for an explicit offline evidence bundle."""

import unicodedata
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    ValidationError,
    model_validator,
)
from pydantic_core import PydanticCustomError

from ..models import PreciseTimestamp
from .errors import IntakeError


def _environment(value: str) -> str:
    try:
        if not value.strip() or len(value.encode("utf-8")) > 128:
            raise ValueError
    except UnicodeEncodeError:
        raise ValueError("invalid environment identifier") from None
    return value


def _ordered(value):
    if type(value) is not list:
        raise ValueError("expected an array")
    return tuple(value)


def _utc_offset(value: str) -> str:
    if value == "-00:00":
        raise ValueError("unknown negative-zero offset")
    return value


def _display_label(value: str) -> str:
    """Accept a readable source name; refuse anything that can deceive a reader.

    The label is written by whoever assembled the bundle and is shown beside
    evidence, so it stays printable text on one line. Control, format and
    separator characters are refused because they can hide or reorder what a
    reviewer sees. The rejected value is never echoed back in the error.
    """
    if not value.strip():
        raise ValueError("blank display label")
    if len(value) > 64:
        raise ValueError("display label too long")
    for character in value:
        if character != " " and unicodedata.category(character)[0] in {"C", "Z"}:
            raise ValueError("display label has a non-printable character")
    return value


SafeLabel = Annotated[
    StrictStr, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
]
EnvironmentId = Annotated[StrictStr, AfterValidator(_environment)]
Digest = Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
BundlePath = Annotated[StrictStr, Field(min_length=1, max_length=4096)]
DisplayLabel = Annotated[StrictStr, AfterValidator(_display_label)]
ExtractionRule = Literal["wazuh-archive-full-log-utf8-v1"]


class _Context(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, hide_input_in_errors=True
    )

    ingested_at: PreciseTimestamp


class WazuhWin4688Context(_Context):
    collection_mode: Literal["direct", "forwarded", "unknown"]


class SuricataWazuhContext(_Context):
    deployment_mode: Literal["ids", "ips", "unknown"]


class SuricataEveContext(_Context):
    sensor_id: SafeLabel
    deployment_mode: Literal["ids", "ips", "unknown"]


class PfSenseFilterlogContext(_Context):
    sensor_id: SafeLabel
    source_year: Annotated[StrictInt, Field(ge=1, le=9999)]
    source_utc_offset: Annotated[
        StrictStr,
        Field(pattern=r"^[+-](?:[01][0-9]|2[0-3]):[0-5][0-9]$"),
        AfterValidator(_utc_offset),
    ]


class CowrieWazuhContext(_Context):
    sensor_id: SafeLabel


class CowrieJsonlContext(_Context):
    sensor_id: SafeLabel


class WazuhCowrieAlertContext(_Context):
    # Same sensor label as the direct Cowrie parsers, so both views derive the
    # same session key; same collection facts as the other Wazuh profiles.
    collection_mode: Literal["direct", "forwarded", "unknown"]
    sensor_id: SafeLabel


ParserContext = (
    WazuhWin4688Context
    | SuricataWazuhContext
    | SuricataEveContext
    | PfSenseFilterlogContext
    | CowrieWazuhContext
    | CowrieJsonlContext
    | WazuhCowrieAlertContext
)
ParserKey = Literal[
    "wazuh-win4688-v2",
    "wazuh-sysmon1-v1",
    "wazuh-powershell4104-v1",
    "wazuh-sysmon3-archive-v1",
    "wazuh-suricata-alert-v1",
    "wazuh-cowrie-alert-v1",
    "suricata-wazuh-alert-v1",
    "suricata-eve-jsonl-v1",
    "pfsense-filterlog-bsd-ipv4-tcp-udp-v1",
    "cowrie-wazuh-v1",
    "cowrie-jsonl-v1",
]

_CONTEXT_TYPES = {
    "wazuh-win4688-v2": WazuhWin4688Context,
    "wazuh-sysmon1-v1": WazuhWin4688Context,
    "wazuh-powershell4104-v1": WazuhWin4688Context,
    # Same caller facts as the other Windows profiles; the record itself
    # is a manager archive line, not a search hit.
    "wazuh-sysmon3-archive-v1": WazuhWin4688Context,
    # A manager alert raised from a Suricata alert: the Wazuh rule is the
    # detection, so the caller facts are the Wazuh ones, not deployment_mode.
    "wazuh-suricata-alert-v1": WazuhWin4688Context,
    "wazuh-cowrie-alert-v1": WazuhCowrieAlertContext,
    "suricata-wazuh-alert-v1": SuricataWazuhContext,
    "suricata-eve-jsonl-v1": SuricataEveContext,
    "pfsense-filterlog-bsd-ipv4-tcp-udp-v1": PfSenseFilterlogContext,
    "cowrie-wazuh-v1": CowrieWazuhContext,
    "cowrie-jsonl-v1": CowrieJsonlContext,
}


class Derivation(BaseModel):
    """How bytes in this entry were extracted from a record held elsewhere.

    Caller-declared provenance. The parent archive is not part of the bundle,
    so nothing here is verified against it; the hash records which record the
    caller says these bytes came from, and the rule records how. Declaring a
    derivation never relaxes an assertion and never changes an identity.
    """

    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, hide_input_in_errors=True
    )

    parent_sha256: Digest
    extraction: ExtractionRule


class BundleFile(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, hide_input_in_errors=True
    )

    path: BundlePath
    source_ref: SafeLabel
    parser: ParserKey
    sha256: Digest
    context: ParserContext
    # Presentation only: the name an operator configured for this source. It is
    # never read out of the evidence, never an observed hostname, and never part
    # of an evidence identity or of any fingerprint an attestation binds to.
    display_label: DisplayLabel | None = None
    # Absent means the bytes are the source file as captured. Present means
    # they were extracted, and the report must say so rather than let a
    # derivative read as a native capture.
    derived_from: Derivation | None = None

    @model_validator(mode="before")
    @classmethod
    def select_context(cls, value):
        if type(value) is not dict:
            return value
        parser = value.get("parser")
        context_type = _CONTEXT_TYPES.get(parser) if type(parser) is str else None
        if context_type is None:
            raise PydanticCustomError("unknown_parser", "unknown parser")
        try:
            context = context_type.model_validate(value.get("context"))
        except ValidationError:
            raise PydanticCustomError("invalid_parser_context", "invalid parser context") from None
        return value | {"context": context}

    @model_validator(mode="after")
    def context_matches_parser(self):
        if type(self.context) is not _CONTEXT_TYPES[self.parser]:
            raise ValueError("parser context mismatch")
        return self

    @model_validator(mode="after")
    def parent_differs_from_these_bytes(self):
        # A derivative cannot be its own parent: equal hashes would mean the
        # bytes were never extracted from anything.
        if self.derived_from is not None and self.derived_from.parent_sha256 == self.sha256:
            raise PydanticCustomError("self_parent", "parent equals these bytes")
        return self


class BundleManifest(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, hide_input_in_errors=True
    )

    bundle_schema_version: Literal["0.1.0"]
    environment_id: EnvironmentId
    files: Annotated[
        tuple[BundleFile, ...], BeforeValidator(_ordered), Field(max_length=100)
    ]

    @model_validator(mode="after")
    def unique_source_refs(self):
        refs = [entry.source_ref for entry in self.files]
        if len(set(refs)) != len(refs):
            raise PydanticCustomError("duplicate_source_ref", "duplicate source ref")
        return self


def _field_from_location(location: tuple[object, ...]) -> str | None:
    allowed = {
        "bundle_schema_version",
        "environment_id",
        "files",
        "path",
        "source_ref",
        "parser",
        "sha256",
        "context",
        "display_label",
        "derived_from",
        "parent_sha256",
        "extraction",
    }
    for item in reversed(location):
        if type(item) is str and item in allowed:
            return item
    return None


def _file_index(location: tuple[object, ...]) -> int | None:
    for position, item in enumerate(location[:-1]):
        if item == "files" and type(location[position + 1]) is int:
            return location[position + 1]
    return None


def parse_manifest(data: dict) -> BundleManifest:
    """Validate one decoded manifest without exposing rejected values."""
    if type(data) is not dict:
        raise IntakeError("invalid_manifest", stage="inputs")
    try:
        return BundleManifest.model_validate(data)
    except ValidationError as error:
        first = error.errors(include_input=False, include_context=False, include_url=False)[0]
        location = first["loc"]
        code = first["type"]
        public_code = (
            "unknown_parser"
            if code == "unknown_parser"
            else "duplicate_source_ref"
            if code == "duplicate_source_ref"
            else "resource_limit"
            if code == "too_long"
            else "invalid_manifest"
        )
        field = (
            "parent_sha256"
            if code == "self_parent"
            else "parser"
            if code == "unknown_parser"
            else "context"
            if code == "invalid_parser_context"
            else _field_from_location(location)
        )
        raise IntakeError(
            public_code,
            stage="inputs",
            file_index=_file_index(location),
            field=field,
        ) from None
