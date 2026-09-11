"""Deterministic result primitives and validated-model fingerprints."""
import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, Field, StrictInt, StrictStr, field_validator

from ..models.canonical_event_v2 import CanonicalEventV2
from ..models.precise_timestamp import PreciseTimestamp
from ..models.scenario import ScenarioManifest
from .contracts import (MAX_EVENTS, AssertionRule, Binding, CollectionDeclaration, Correlation, Digest,
    EvaluationContext, EvaluationProfile, FinalStatus, FrozenContract, JoinPair, NonBlank, Outcome,
    Predicate, Role, Version, ordered)
from .errors import ValidationEngineError


# Evidence coordinates retain the canonical contract's text domain. The 4 KiB
# operand budget applies to predicates/bindings, not existing evidence identity.
EvidenceText = Annotated[StrictStr, Field(min_length=1, pattern=r"\S")]


class WitnessPair(FrozenContract):
    target_event_id: EvidenceText
    anchor_event_id: EvidenceText


EvidenceIds = Annotated[tuple[EvidenceText, ...], BeforeValidator(ordered)]


class AssertionResult(FrozenContract):
    assertion_id: NonBlank
    role: Role
    outcome: Outcome
    reason_code: NonBlank
    evidence_ids: EvidenceIds = ()
    witness_pairs: Annotated[tuple[WitnessPair, ...], BeforeValidator(ordered)] = ()
    unevaluable_evidence_ids: EvidenceIds = ()
    collection_reference: NonBlank | None = None
    collection_assurance: Literal["unknown", "caller-attested"] = "unknown"

    @field_validator("evidence_ids", "unevaluable_evidence_ids")
    @classmethod
    def stable_ids(cls, value):
        return tuple(sorted(set(value)))

    @field_validator("witness_pairs")
    @classmethod
    def stable_pairs(cls, value):
        return tuple(sorted(set(value), key=lambda pair: (pair.target_event_id, pair.anchor_event_id)))


class EvidenceEntry(FrozenContract):
    event_id: EvidenceText
    raw_event_ref: EvidenceText
    raw_event_hash: Digest
    canonical_schema_version: Literal["2.0"] = "2.0"


Count = Annotated[StrictInt, Field(ge=0)]


class OutcomeCounts(FrozenContract):
    satisfied: Count = 0
    missing_telemetry: Count = 0
    false_negative: Count = 0
    inconclusive: Count = 0


class EvaluationResult(FrozenContract):
    result_schema_version: Literal["0.1.0"] = "0.1.0"
    engine_semantics_version: Literal["0.1.0"] = "0.1.0"
    run_id: NonBlank
    scenario_id: NonBlank
    scenario_version: Version
    profile_id: NonBlank
    profile_version: Version
    scenario_fingerprint: Digest
    profile_fingerprint: Digest
    scope_fingerprint: Digest
    context_fingerprint: Digest
    event_set_fingerprint: Digest
    final_status: FinalStatus
    assertions: Annotated[tuple[AssertionResult, ...], BeforeValidator(ordered), Field(min_length=1, max_length=100)]
    counts: OutcomeCounts
    evidence_index: Annotated[tuple[EvidenceEntry, ...], BeforeValidator(ordered)] = ()

    @field_validator("evidence_index")
    @classmethod
    def stable_index(cls, value):
        if len({entry.event_id for entry in value}) != len(value):
            raise ValueError("duplicate evidence index ID")
        return tuple(sorted(value, key=lambda entry: entry.event_id))


_FINGERPRINT_MODELS = (ScenarioManifest, CanonicalEventV2, AssertionRule, Binding, CollectionDeclaration,
    Correlation, EvaluationContext, EvaluationProfile, JoinPair, Predicate, WitnessPair, AssertionResult,
    EvidenceEntry, OutcomeCounts, EvaluationResult)


def _plain_fields(value):
    """Preserve malformed field types until validation; never serialize first."""
    if isinstance(value, PreciseTimestamp):
        # parse(instance) trusts it; rebuilding components checks forged/copy states.
        return PreciseTimestamp._from_parts(value._seconds, value._nanos, value._digits)
    if isinstance(value, BaseModel):
        values = dict(value.__dict__)
        if value.__pydantic_extra__:
            values.update(value.__pydantic_extra__)
        return {key: _plain_fields(item) for key, item in values.items()}
    if isinstance(value, dict):
        return {key: _plain_fields(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_plain_fields(item) for item in value)
    return value


def revalidate_typed(value, model_type):
    """Shared boundary helper; downstream input validation may wrap safe error codes."""
    if type(value) is not model_type:
        raise ValidationEngineError("invalid_input")
    try:
        return model_type.model_validate(_plain_fields(value))
    except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        raise ValidationEngineError("invalid_input") from None


def _hash_json(value):
    try:
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ValidationEngineError("invalid_input") from None


def fingerprint(value):
    if type(value) not in _FINGERPRINT_MODELS:
        raise ValidationEngineError("invalid_input")
    validated = revalidate_typed(value, type(value))
    return _hash_json(validated.model_dump(mode="json"))


def scenario_fingerprint(manifest):
    return fingerprint(revalidate_typed(manifest, ScenarioManifest))


def profile_fingerprint(profile):
    return fingerprint(revalidate_typed(profile, EvaluationProfile))


def scope_fingerprint(context):
    validated = revalidate_typed(context, EvaluationContext)
    return _hash_json(validated.model_dump(mode="json", exclude={"declarations"}))


def validated_events(events):
    if type(events) not in (list, tuple):
        raise ValidationEngineError("invalid_input", ("events",))
    if len(events) > MAX_EVENTS:
        raise ValidationEngineError("resource_limit", ("events",))
    validated = tuple(revalidate_typed(event, CanonicalEventV2) for event in events)
    if len({event.event_id for event in validated}) != len(validated):
        raise ValidationEngineError("duplicate_evidence_id", ("events",))
    return tuple(sorted(validated, key=lambda event: event.event_id))


def event_set_fingerprint(events):
    return _hash_json([event.model_dump(mode="json") for event in validated_events(events)])


def aggregate_status(expected_outcome, outcomes):
    if expected_outcome not in {"detected", "prevented"} or type(outcomes) not in (list, tuple) or not outcomes:
        raise ValidationEngineError("invalid_input")
    if any(outcome not in {"satisfied", "missing_telemetry", "false_negative", "inconclusive"} for outcome in outcomes):
        raise ValidationEngineError("invalid_input")
    for outcome, status in (("inconclusive", "Inconclusive"), ("missing_telemetry", "Missing telemetry"),
                            ("false_negative", "False negative")):
        if outcome in outcomes:
            return status
    return "Detected" if expected_outcome == "detected" else "Prevented"


def count_outcomes(assertions):
    counts = dict(satisfied=0, missing_telemetry=0, false_negative=0, inconclusive=0)
    for assertion in assertions:
        counts[assertion.outcome] += 1
    return OutcomeCounts(**counts)


def build_evidence_index(events, evidence_ids):
    by_id = {event.event_id: event for event in validated_events(events)}
    entries = []
    for identifier in sorted(set(evidence_ids)):
        if identifier not in by_id:
            raise ValidationEngineError("invalid_input")
        event = by_id[identifier]
        entries.append(EvidenceEntry(event_id=event.event_id, raw_event_ref=event.raw_event_ref,
            raw_event_hash=event.raw_event_hash, canonical_schema_version=event.schema_version))
    return tuple(entries)
