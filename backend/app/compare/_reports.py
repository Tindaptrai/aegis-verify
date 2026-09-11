"""Validate report consistency without replaying evidence or opening raw refs."""

from pydantic import ValidationError

from ..intake import IntakeError
from ..models.scenario import ScenarioManifest
from ..validation import (
    EvaluationContext, EvaluationProfile, EvaluationResult, ValidationEngineError,
    fingerprint, profile_fingerprint, scenario_fingerprint, scope_fingerprint,
)
from ..validation.results import aggregate_status, count_outcomes


def invalid(field="evaluation", *, code="invalid_comparison_input"):
    raise IntakeError(code, stage="comparison", field=field)


def _assertions(evaluation, manifest, profile, context):
    assertions = {item.assertion_id: item for item in evaluation.assertions}
    rules = {item.assertion_id: item for item in profile.rules}
    expected = {item.id for item in manifest.assertions}
    if len(assertions) != len(evaluation.assertions) or set(assertions) != expected or set(rules) != expected:
        invalid("assertions")
    if evaluation.counts != count_outcomes(evaluation.assertions):
        invalid("counts")
    if evaluation.final_status != aggregate_status(manifest.expected_outcome, tuple(a.outcome for a in evaluation.assertions)):
        invalid("final_status")

    index = {entry.event_id: entry for entry in evaluation.evidence_index}
    declarations = {item.assertion_id: item for item in context.declarations}
    for declaration in context.declarations:
        rule = rules.get(declaration.assertion_id)
        if rule is None or rule.role != "detection" or rule.capability != "supported":
            invalid("declarations")
        for field in ("profile_fingerprint", "scope_fingerprint", "event_set_fingerprint"):
            value = getattr(declaration, field)
            if value is not None and value != getattr(evaluation, field):
                invalid("declarations")
        if declaration.status == "complete_for_scope" and (
            declaration.coverage_start > context.start or declaration.coverage_end < context.end
        ):
            invalid("declarations")

    referenced = set()
    for item in evaluation.assertions:
        rule = rules[item.assertion_id]
        if item.role != rule.role:
            invalid("assertions")
        ids = set(item.evidence_ids)
        unknown = set(item.unevaluable_evidence_ids)
        if not (ids | unknown) <= index.keys():
            invalid("evidence_ids", code="comparison_missing_evidence_reference")
        referenced.update(ids | unknown)
        pairs = item.witness_pairs
        pair_ids = {i for pair in pairs for i in (pair.target_event_id, pair.anchor_event_id)}
        if not pair_ids <= index.keys():
            invalid("witness_pairs", code="comparison_missing_evidence_reference")
        if pairs:
            if rule.correlation is None or item.outcome != "satisfied" or pair_ids != ids:
                invalid("witness_pairs")
            anchors = set(assertions[rule.correlation.anchor_assertion_id].evidence_ids)
            if any(p.anchor_event_id not in anchors or p.target_event_id == p.anchor_event_id for p in pairs):
                invalid("witness_pairs")
        elif item.outcome == "satisfied" and rule.correlation is not None:
            invalid("witness_pairs")

        declaration = declarations.get(item.assertion_id)
        assurance = "caller-attested" if declaration and declaration.status == "complete_for_scope" else "unknown"
        reference = declaration.reference if declaration else None
        if item.collection_assurance != assurance or item.collection_reference != reference:
            invalid("declarations")
        reasons = {
            "satisfied": {"witness_found"},
            "false_negative": {"expected_detection_absent"},
            "missing_telemetry": {"activity_not_found_in_input", "missing_activity_anchor"},
            "inconclusive": {"uncertain_activity_anchor", "insufficient_fields", "collection_not_confirmed",
                             "incomplete_detection_window", "prevention_not_demonstrated", "unsupported_requirement"},
        }
        if item.reason_code not in reasons[item.outcome]:
            invalid("assertions")
        if rule.capability == "unsupported":
            if (item.outcome, item.reason_code) != ("inconclusive", "unsupported_requirement") or ids or unknown or pairs:
                invalid("assertions")
        elif item.reason_code == "unsupported_requirement":
            invalid("assertions")
        if item.outcome == "satisfied" and not ids:
            invalid("evidence_ids")
        if item.outcome == "false_negative" and (
            item.role != "detection" or assurance != "caller-attested" or not ids or unknown
        ):
            invalid("assertions")
        if item.outcome != "satisfied" and pairs:
            invalid("witness_pairs")
        if rule.role == "telemetry":
            if item.reason_code not in {"witness_found", "activity_not_found_in_input", "insufficient_fields", "unsupported_requirement"}:
                invalid("assertions")
            if item.outcome != "satisfied" and ids:
                invalid("evidence_ids")
        elif rule.capability == "supported":
            anchor = assertions[rule.correlation.anchor_assertion_id]
            if item.reason_code == "missing_activity_anchor":
                if anchor.outcome != "missing_telemetry" or ids or unknown:
                    invalid("assertions")
            elif item.reason_code == "uncertain_activity_anchor":
                if anchor.outcome != "inconclusive" or ids or unknown != set(anchor.unevaluable_evidence_ids):
                    invalid("assertions")
            elif anchor.outcome != "satisfied":
                invalid("assertions")
            elif item.outcome != "satisfied" and ids != set(anchor.evidence_ids):
                invalid("evidence_ids")
        if item.reason_code == "insufficient_fields" and not unknown:
            invalid("evidence_ids")
        if item.reason_code == "collection_not_confirmed" and assurance != "unknown":
            invalid("declarations")
        if item.reason_code in {"expected_detection_absent", "collection_not_confirmed", "incomplete_detection_window"} and item.role != "detection":
            invalid("assertions")
        if item.reason_code == "prevention_not_demonstrated" and item.role != "prevention":
            invalid("assertions")
    if referenced != index.keys():
        invalid("evidence_ids")


def validate_report(payload):
    if type(payload) is not dict or payload.get("kind") != "evaluation":
        invalid("kind")
    if payload.get("cli_report_version") != "0.1.0":
        invalid("cli_report_version")
    inputs = payload.get("comparison_inputs")
    if type(inputs) is not dict or set(inputs) != {"version", "scenario", "profile", "context"} or inputs["version"] != "0.1.0":
        invalid("comparison_inputs")
    try:
        manifest = ScenarioManifest.model_validate(inputs["scenario"])
        profile = EvaluationProfile.model_validate(inputs["profile"])
        context = EvaluationContext.model_validate(inputs["context"])
        data = payload.get("evaluation")
        if type(data) is not dict or any(data.get(key) != "0.1.0" for key in ("result_schema_version", "engine_semantics_version")):
            invalid("evaluation")
        evaluation = EvaluationResult.model_validate(data)
        hashes = {
            "scenario_fingerprint": scenario_fingerprint(manifest),
            "profile_fingerprint": profile_fingerprint(profile),
            "scope_fingerprint": scope_fingerprint(context),
            "context_fingerprint": fingerprint(context),
        }
    except (ValidationError, ValidationEngineError, ValueError, TypeError):
        invalid()
    scenario = payload.get("scenario")
    if type(scenario) is not dict:
        invalid("scenario")
    for field, value in (("id", manifest.id), ("version", manifest.version)):
        if scenario.get(field) != value or getattr(evaluation, "scenario_" + field) != value or getattr(profile, "scenario_" + field) != value:
            invalid("scenario_" + field, code="comparison_incompatible")
    if scenario.get("name") != manifest.name:
        invalid("scenario")
    if evaluation.run_id != context.run_id:
        invalid("context")
    for field in ("profile_id", "profile_version"):
        if getattr(evaluation, field) != getattr(profile, field):
            invalid(field)
    if profile.scenario_fingerprint != hashes["scenario_fingerprint"]:
        invalid("scenario_fingerprint")
    for field, value in hashes.items():
        if getattr(evaluation, field) != value:
            invalid(field)
    _assertions(evaluation, manifest, profile, context)
    return {
        "scenario_id": manifest.id, "scenario_name": manifest.name, "scenario_version": manifest.version,
        "profile_id": profile.profile_id, "profile_version": profile.profile_version,
        **hashes, "evaluation": evaluation, "context": context,
        "evidence_index": {entry.event_id: entry for entry in evaluation.evidence_index},
    }
