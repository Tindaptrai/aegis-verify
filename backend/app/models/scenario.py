"""Reviewed scenario expectations, not executable predicates or run results."""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel, BeforeValidator, ConfigDict, Field, StrictBool, StrictStr,
    ValidationError, field_validator, model_validator,
)
from pydantic_core import PydanticCustomError


class ScenarioSource(StrEnum):
    SYSMON = "sysmon"
    POWERSHELL = "powershell"
    WAZUH = "wazuh"
    SURICATA = "suricata"
    PFSENSE = "pfsense"
    COWRIE = "cowrie"


class ExpectedOutcome(StrEnum):
    DETECTED = "detected"
    PREVENTED = "prevented"


def _enum_text(value: object) -> object:
    if not isinstance(value, str):
        raise ValueError("expected enum text")
    return value


def _ordered(value: object) -> object:
    if not isinstance(value, (list, tuple)):
        raise ValueError("expected list or tuple")
    return value


NonBlank = Annotated[StrictStr, Field(min_length=1, pattern=r"\S")]
ScenarioId = Annotated[StrictStr, Field(pattern=r"^SCN-[0-9]{3}$")]
AssertionId = Annotated[StrictStr, Field(pattern=r"^SCN-[0-9]{3}-A[0-9]{2}$")]
Version = Annotated[StrictStr, Field(pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")]
Source = Annotated[ScenarioSource, BeforeValidator(_enum_text)]


class _FrozenContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class ScenarioSafety(_FrozenContract):
    destructive: StrictBool
    authorization_required: StrictBool
    notes: NonBlank

    @field_validator("destructive")
    @classmethod
    def require_non_destructive(cls, value: bool) -> bool:
        if value:
            raise ValueError("V0 requires non-destructive scenarios")
        return value

    @field_validator("authorization_required")
    @classmethod
    def require_authorization(cls, value: bool) -> bool:
        if not value:
            raise ValueError("V0 requires authorization before execution")
        return value


class ScenarioAssertion(_FrozenContract):
    id: AssertionId
    description: NonBlank
    source: Source


class ScenarioManifest(_FrozenContract):
    id: ScenarioId
    name: NonBlank
    version: Version
    status: Literal["draft"]
    description: NonBlank
    safety: ScenarioSafety
    expected_sources: Annotated[
        tuple[Source, ...], Field(min_length=1), BeforeValidator(_ordered),
    ]
    expected_outcome: Annotated[ExpectedOutcome, BeforeValidator(_enum_text)]
    assertions: Annotated[
        tuple[ScenarioAssertion, ...], Field(min_length=1), BeforeValidator(_ordered),
    ]
    tags: Annotated[tuple[NonBlank, ...], BeforeValidator(_ordered)] | None = None

    @model_validator(mode="after")
    def validate_relations(self) -> "ScenarioManifest":
        errors = []

        def invalid(location: tuple[str | int, ...], code: str, message: str) -> None:
            errors.append({"type": PydanticCustomError(code, message), "loc": location})

        sources = set()
        for index, source in enumerate(self.expected_sources):
            if source in sources:
                invalid(("expected_sources", index), "duplicate_source", "source is duplicated")
            sources.add(source)

        identifiers = set()
        referenced = set()
        for index, assertion in enumerate(self.assertions):
            if assertion.id in identifiers:
                invalid(("assertions", index, "id"), "duplicate_assertion_id", "assertion ID is duplicated")
            identifiers.add(assertion.id)
            if not assertion.id.startswith(self.id + "-A"):
                invalid(("assertions", index, "id"), "assertion_parent", "assertion ID must belong to this scenario")
            if assertion.source not in sources:
                invalid(("assertions", index, "source"), "undeclared_source", "assertion source must be declared")
            referenced.add(assertion.source)

        for index, source in enumerate(self.expected_sources):
            if source not in referenced:
                invalid(("expected_sources", index), "unreferenced_source", "source needs an assertion")

        if errors:
            raise ValidationError.from_exception_data(type(self).__name__, errors, hide_input=True)
        return self
