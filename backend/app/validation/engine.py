"""Bounded evaluation of offline canonical evidence."""
from ._inputs import validate_inputs
from ..models.canonical_event_v2 import CanonicalEventV2
from ..models.scenario import ScenarioManifest
from .contracts import MAX_COMPARISONS, EvaluationContext, EvaluationProfile
from .errors import ValidationEngineError
from .predicates import Truth, all_of, evaluate_conditions, evaluate_joins
from .results import (AssertionResult, EvaluationResult, WitnessPair, aggregate_status,
                      build_evidence_index, count_outcomes)


class _Budget:
    def __init__(self):
        self.comparisons = 0

    def charge(self):
        self.comparisons += 1
        if self.comparisons > MAX_COMPARISONS:
            raise ValidationEngineError("resource_limit")


def _candidates(rule, events, context, bindings, budget):
    for event in events:
        if (event.environment_id != context.environment_id or event.source_type != rule.source_type or
                not context.start <= event.timestamp <= context.end):
            continue
        budget.charge()
        truth = evaluate_conditions(event, rule.scope + rule.match, bindings)
        if truth is not Truth.FALSE:
            yield event, truth


def _result(rule, outcome, reason, **details):
    return AssertionResult(assertion_id=rule.assertion_id, role=rule.role,
                           outcome=outcome, reason_code=reason, **details)


def _telemetry(rule, events, context, bindings, budget):
    evidence, unknown = [], []
    for event, truth in _candidates(rule, events, context, bindings, budget):
        (evidence if truth is Truth.TRUE else unknown).append(event.event_id)
    outcome, reason = ("satisfied", "witness_found") if evidence else (
        ("inconclusive", "insufficient_fields") if unknown else ("missing_telemetry", "activity_not_found_in_input"))
    return _result(rule, outcome, reason, evidence_ids=evidence, unevaluable_evidence_ids=unknown)


def _target(rule, anchor_result, events, by_id, context, bindings, declaration, budget):
    assurance = dict(collection_reference=declaration.reference if declaration else None,
        collection_assurance="caller-attested" if declaration and declaration.status == "complete_for_scope" else "unknown")
    if anchor_result.outcome == "missing_telemetry":
        return _result(rule, "missing_telemetry", "missing_activity_anchor", **assurance)
    if anchor_result.outcome != "satisfied":
        return _result(rule, "inconclusive", "uncertain_activity_anchor",
                       unevaluable_evidence_ids=anchor_result.unevaluable_evidence_ids, **assurance)
    correlation = rule.correlation
    anchors = tuple(by_id[identifier] for identifier in anchor_result.evidence_ids)
    # A satisfied root can still have other potential activities. Their unknown
    # root predicates must participate in the conjunction for each target pair.
    anchor_candidates = tuple((anchor, Truth.TRUE) for anchor in anchors) + tuple(
        (by_id[identifier], Truth.UNKNOWN) for identifier in anchor_result.unevaluable_evidence_ids)
    pairs, unknown = [], set()
    for target, candidate_truth in _candidates(rule, events, context, bindings, budget):
        for anchor, anchor_truth in anchor_candidates:
            if target.event_id == anchor.event_id:
                continue
            budget.charge()
            delta = target.timestamp.epoch_nanoseconds - anchor.timestamp.epoch_nanoseconds
            if not correlation.min_delta_ns <= delta <= correlation.max_delta_ns:
                continue
            truth = all_of((candidate_truth, anchor_truth, evaluate_joins(target, anchor, correlation.join_pairs)))
            if truth is Truth.TRUE:
                pairs.append(WitnessPair(target_event_id=target.event_id, anchor_event_id=anchor.event_id))
            elif truth is Truth.UNKNOWN:
                unknown.add(target.event_id)
                if anchor_truth is Truth.UNKNOWN or any(getattr(anchor, pair.anchor_field) is None for pair in correlation.join_pairs):
                    unknown.add(anchor.event_id)
    if pairs:
        evidence = {identifier for pair in pairs for identifier in (pair.target_event_id, pair.anchor_event_id)}
        return _result(rule, "satisfied", "witness_found", evidence_ids=tuple(evidence),
                       witness_pairs=pairs, unevaluable_evidence_ids=tuple(unknown), **assurance)
    details = dict(evidence_ids=anchor_result.evidence_ids, unevaluable_evidence_ids=tuple(unknown), **assurance)
    if unknown:
        return _result(rule, "inconclusive", "insufficient_fields", **details)
    if rule.role == "prevention":
        return _result(rule, "inconclusive", "prevention_not_demonstrated", **details)
    # Context endpoints are validated calendar instants. Containment in these
    # integer bounds also excludes intervals extending beyond timestamp range.
    for anchor in anchors:
        start = anchor.timestamp.epoch_nanoseconds + correlation.min_delta_ns
        end = anchor.timestamp.epoch_nanoseconds + correlation.max_delta_ns
        if start < context.start.epoch_nanoseconds or end > context.end.epoch_nanoseconds:
            return _result(rule, "inconclusive", "incomplete_detection_window", **details)
    if not declaration or declaration.status != "complete_for_scope":
        return _result(rule, "inconclusive", "collection_not_confirmed", **details)
    return _result(rule, "false_negative", "expected_detection_absent", **details)


def evaluate_scenario(
    manifest: ScenarioManifest,
    events: list[CanonicalEventV2] | tuple[CanonicalEventV2, ...],
    *,
    profile: EvaluationProfile,
    context: EvaluationContext,
) -> EvaluationResult:
    """Evaluate existential witnesses from revalidated canonical V2 inputs.

    Collection assurance is caller-attested; raw references are never opened.
    A resource error aborts the whole evaluation without returning a partial verdict.
    """
    manifest, events, profile, context, hashes = validate_inputs(manifest, events, profile, context)
    budget = _Budget()
    by_id = {event.event_id: event for event in events}
    bindings = {binding.name: binding.value for binding in context.bindings}
    declarations = {declaration.assertion_id: declaration for declaration in context.declarations}
    outcomes = {}
    for rule in profile.rules:
        if rule.capability == "unsupported":
            outcomes[rule.assertion_id] = _result(rule, "inconclusive", "unsupported_requirement")
        elif rule.role == "telemetry":
            outcomes[rule.assertion_id] = _telemetry(rule, events, context, bindings, budget)
    for rule in profile.rules:
        if rule.capability == "supported" and rule.role != "telemetry":
            outcomes[rule.assertion_id] = _target(rule, outcomes[rule.correlation.anchor_assertion_id], events,
                by_id, context, bindings, declarations.get(rule.assertion_id), budget)
    assertions = tuple(outcomes[assertion.id] for assertion in manifest.assertions)
    referenced = {identifier for assertion in assertions for identifier in
                  assertion.evidence_ids + assertion.unevaluable_evidence_ids}
    referenced.update(identifier for assertion in assertions for pair in assertion.witness_pairs
                      for identifier in (pair.target_event_id, pair.anchor_event_id))
    return EvaluationResult(run_id=context.run_id, scenario_id=manifest.id, scenario_version=manifest.version,
        profile_id=profile.profile_id, profile_version=profile.profile_version, **hashes,
        final_status=aggregate_status(manifest.expected_outcome, tuple(a.outcome for a in assertions)),
        assertions=assertions, counts=count_outcomes(assertions), evidence_index=build_evidence_index(events, referenced))
