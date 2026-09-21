"""Reusable orchestration from reviewed local inputs to the validation engine."""

from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

from pydantic import ValidationError

from .._scenario_yaml import MAX_BYTES as MAX_SCENARIO_BYTES
from ..intake import (
    IntakeError,
    check_collection,
    decode_config,
    load_bundle,
    local_path,
    parse_manifest,
    read_local,
)
from ..intake.io import MAX_CONFIG_BYTES
from ..scenario_loader import ScenarioLoadError, parse_scenario_yaml
from ..validation import (
    EvaluationContext,
    EvaluationProfile,
    ValidationEngineError,
    evaluate_scenario,
)
from .reporting import CLI_REPORT_VERSION


_SCENARIO_LABEL = "<selected-scenario>"


def _selected_json(path, *, stage: str, model_type):
    raw = read_local(path, limit=MAX_CONFIG_BYTES, stage=stage)
    data = decode_config(raw, stage=stage)
    try:
        value = model_type.model_validate(data)
    except ValidationError:
        code = "invalid_profile" if stage == "profile" else "invalid_context"
        raise IntakeError(code, stage=stage) from None
    return value, raw


def _scenario(path):
    raw = read_local(path, limit=MAX_SCENARIO_BYTES, stage="scenario")
    try:
        text = raw.decode("utf-8")
        manifest = parse_scenario_yaml(text, source_name=_SCENARIO_LABEL)
    except (UnicodeError, ScenarioLoadError):
        raise IntakeError("invalid_scenario", stage="scenario") from None
    return manifest, raw


def _engine_error(error: ValidationEngineError) -> IntakeError:
    first = error.path[0] if error.path else None
    stage = {
        "manifest": "scenario",
        "profile": "profile",
        "context": "context",
        "declarations": "collection",
        "events": "evidence",
    }.get(first, "inputs")
    field = next(
        (item for item in reversed(error.path) if type(item) is str),
        None,
    )
    return IntakeError(error.code, stage=stage, field=field)


TIMELINE_VERSION = "0.2.0"
_TIMELINE_FIELDS = (
    "source_type", "event_provider", "hostname", "event_action", "rule_id", "signature_id",
    "process_name", "raw_event_ref",
)


def evidence_timeline(events, evaluation, *, sources=None) -> dict:
    """Order the referenced evidence by its own timestamps; copy values, never fill them.

    Only events the evaluation referenced (evidence or unevaluable candidates)
    appear, in ascending event time with event ID as the tie-break. Every value
    is the canonical field as parsed, so an absent field stays ``null``. The
    dashboard renders this order and must not reorder or derive missing times.

    ``sources`` maps an event ID to the bundle entry that produced it, as
    ``(source_ref, display_label)``. Both are caller-configured identity, kept
    apart from the observed ``hostname``; an event the caller did not map keeps
    ``null`` for both rather than being guessed from its type or bytes.
    """
    referenced = {entry.event_id for entry in evaluation.evidence_index}
    by_event = dict(sources or {})
    entries = []
    for event in events:
        if event.event_id not in referenced:
            continue
        values = {"event_id": event.event_id, "timestamp": event.timestamp.isoformat(),
                  "ingested_at": event.ingested_at.isoformat()}
        for field in _TIMELINE_FIELDS:
            values[field] = getattr(event, field)
        source_ref, source_label = by_event.get(event.event_id, (None, None))
        values["source_ref"] = source_ref
        values["source_label"] = source_label
        entries.append((event.timestamp.epoch_nanoseconds, event.event_id, values))
    entries.sort(key=lambda item: (item[0], item[1]))
    return {
        "version": TIMELINE_VERSION,
        "order": "timestamp_then_event_id",
        "events": [item[2] for item in entries],
    }


def _sources(intake) -> dict:
    """Map each parsed event to the bundle entry a reader can look it up in.

    The ledger already records which entry produced which event, so nothing new
    is inferred here. An entry without a configured label contributes ``None``.
    """
    labels = {item["source_ref"]: item["display_label"] for item in intake.inventory}
    return {
        item.event_id: (item.source_ref, labels.get(item.source_ref))
        for item in intake.ledger
        if item.event_id is not None
    }


def evaluate_bundle(scenario, fixture, *, profile=None, context=None) -> dict:
    """Evaluate one explicit local snapshot without fallback or inferred values."""
    scenario_manifest, scenario_raw = _scenario(scenario)
    root = local_path(fixture, directory=True, stage="inputs")

    inputs_path = root / "inputs.json"
    inputs_raw = read_local(inputs_path, limit=MAX_CONFIG_BYTES, stage="inputs")
    bundle_manifest = parse_manifest(decode_config(inputs_raw, stage="inputs"))

    profile_path = profile if profile is not None else root / "profile.json"
    context_path = context if context is not None else root / "context.json"
    selected_profile, profile_raw = _selected_json(
        profile_path, stage="profile", model_type=EvaluationProfile
    )
    selected_context, context_raw = _selected_json(
        context_path, stage="context", model_type=EvaluationContext
    )
    if bundle_manifest.environment_id != selected_context.environment_id:
        raise IntakeError("environment_mismatch", stage="context", field="environment_id")

    intake = load_bundle(root, bundle_manifest)
    check_collection(intake, selected_profile, selected_context)
    try:
        evaluation = evaluate_scenario(
            scenario_manifest,
            intake.events,
            profile=selected_profile,
            context=selected_context,
        )
    except ValidationEngineError as error:
        raise _engine_error(error) from None

    ledger = []
    for item in intake.ledger:
        values = asdict(item)
        values["warnings"] = list(values["warnings"])
        ledger.append(values)
    return {
        "timeline": evidence_timeline(intake.events, evaluation, sources=_sources(intake)),
        "cli_report_version": CLI_REPORT_VERSION,
        "kind": "evaluation",
        "scenario": {
            "id": scenario_manifest.id,
            "name": scenario_manifest.name,
            "version": scenario_manifest.version,
        },
        "evaluation": evaluation.model_dump(mode="json"),
        "comparison_inputs": {
            "version": "0.1.0",
            "scenario": scenario_manifest.model_dump(mode="json"),
            "profile": selected_profile.model_dump(mode="json"),
            "context": selected_context.model_dump(mode="json"),
        },
        "intake": {
            "inventory": [dict(item) for item in intake.inventory],
            "ledger": ledger,
        },
        "counts": {
            "parsed": len(intake.events),
            "skipped": sum(item.status == "skipped" for item in intake.ledger),
            "referenced": len(evaluation.evidence_index),
        },
        "input_fingerprints": {
            "scenario": sha256(scenario_raw).hexdigest(),
            "inputs": sha256(inputs_raw).hexdigest(),
            "profile": sha256(profile_raw).hexdigest(),
            "context": sha256(context_raw).hexdigest(),
        },
    }
