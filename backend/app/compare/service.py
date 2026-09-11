"""Pure comparison logic for offline validation runs."""

from collections import Counter
from pathlib import Path
from typing import Any

from ..intake import IntakeError, decode_config, read_local
from ..intake.io import MAX_CONFIG_BYTES
from ._reports import validate_report


COMPARISON_KIND = "comparison"


def _comparison_error(*, code: str = "comparison_incompatible", field: str | None = None) -> None:
    raise IntakeError(code, stage="comparison", field=field)


def _load_evaluation(path: str | Path) -> dict[str, Any]:
    raw = read_local(path, limit=MAX_CONFIG_BYTES, stage="comparison")
    return validate_report(decode_config(raw, stage="comparison"))


def _trace_evidence(evidence_index: dict[str, Any], event_ids: tuple[str, ...]) -> list[dict[str, str]]:
    traced = []
    for identifier in event_ids:
        entry = evidence_index.get(identifier)
        if entry is None:
            _comparison_error(code="comparison_missing_evidence_reference", field="evidence_ids")
        traced.append(
            {
                "event_id": entry.event_id,
                "raw_event_ref": entry.raw_event_ref,
                "raw_event_hash": entry.raw_event_hash,
            }
        )
    return traced


def _assertion_state(before_outcome: str, after_outcome: str) -> str:
    unknown = {"inconclusive", "missing_telemetry"}
    if before_outcome in unknown and after_outcome in unknown:
        return "unchanged_unknown" if before_outcome == after_outcome else "unknown_changed"
    if before_outcome in unknown:
        return "became_evaluable"
    if after_outcome in unknown:
        return "became_unevaluable"
    before_pass = before_outcome == "satisfied"
    after_pass = after_outcome == "satisfied"
    if before_pass and after_pass:
        return "unchanged_pass"
    if before_pass and not after_pass:
        return "regression"
    if not before_pass and after_pass:
        return "improvement"
    return "unchanged_fail"


def _state_status(counts: Counter[str]) -> str:
    if counts["regression"] > 0:
        return "Regression"
    if any(counts[key] for key in ("unchanged_unknown", "unknown_changed", "became_evaluable", "became_unevaluable")):
        return "Inconclusive"
    if counts["improvement"] > 0:
        if counts["unchanged_fail"] > 0:
            return "Improved with remaining gaps"
        return "Regression Passed"
    if counts["unchanged_fail"] > 0 and counts["unchanged_pass"] > 0:
        return "Unchanged mixed"
    if counts["unchanged_pass"] > 0:
        return "Unchanged pass"
    if counts["unchanged_fail"] > 0:
        return "Unchanged fail"
    return "No assertions"


def _assertions_payload(before, after) -> tuple[tuple[dict[str, Any], ...], Counter[str], int]:
    before_assertions = {item.assertion_id: item for item in before["evaluation"].assertions}
    after_assertions = {item.assertion_id: item for item in after["evaluation"].assertions}
    if before_assertions.keys() != after_assertions.keys():
        _comparison_error(field="assertions")

    before_index = before["evidence_index"]
    after_index = after["evidence_index"]

    counts = Counter()
    comparisons = []
    for assertion_id in sorted(before_assertions):
        before_assertion = before_assertions[assertion_id]
        after_assertion = after_assertions[assertion_id]
        state = _assertion_state(before_assertion.outcome, after_assertion.outcome)
        counts[state] += 1
        before_trace = _trace_evidence(before_index, before_assertion.evidence_ids)
        after_trace = _trace_evidence(after_index, after_assertion.evidence_ids)
        before_unevaluable = _trace_evidence(before_index, before_assertion.unevaluable_evidence_ids)
        after_unevaluable = _trace_evidence(after_index, after_assertion.unevaluable_evidence_ids)
        comparisons.append(
            {
                "assertion_id": assertion_id,
                "state": state,
                "evidence_changes": {
                    "added": sorted(set(after_assertion.evidence_ids) - set(before_assertion.evidence_ids)),
                    "removed": sorted(set(before_assertion.evidence_ids) - set(after_assertion.evidence_ids)),
                    "retained": sorted(set(before_assertion.evidence_ids) & set(after_assertion.evidence_ids)),
                },
                "before": {
                    "witness_pairs": [pair.model_dump() for pair in before_assertion.witness_pairs],
                    "outcome": before_assertion.outcome,
                    "reason_code": before_assertion.reason_code,
                    "evidence_ids": list(before_assertion.evidence_ids),
                    "evidence_refs": before_trace,
                    "unevaluable_evidence_ids": list(before_assertion.unevaluable_evidence_ids),
                    "unevaluable_evidence_refs": before_unevaluable,
                    "collection_assurance": before_assertion.collection_assurance,
                    "collection_reference": before_assertion.collection_reference,
                },
                "after": {
                    "witness_pairs": [pair.model_dump() for pair in after_assertion.witness_pairs],
                    "outcome": after_assertion.outcome,
                    "reason_code": after_assertion.reason_code,
                    "evidence_ids": list(after_assertion.evidence_ids),
                    "evidence_refs": after_trace,
                    "unevaluable_evidence_ids": list(after_assertion.unevaluable_evidence_ids),
                    "unevaluable_evidence_refs": after_unevaluable,
                    "collection_assurance": after_assertion.collection_assurance,
                    "collection_reference": after_assertion.collection_reference,
                },
            }
        )
    return tuple(comparisons), counts, len(comparisons)


def _run_payload(run) -> dict[str, Any]:
    evaluation = run["evaluation"]
    return {
        "run_id": evaluation.run_id,
        "final_status": evaluation.final_status,
        "profile_id": evaluation.profile_id,
        "profile_version": evaluation.profile_version,
        "profile_fingerprint": evaluation.profile_fingerprint,
        "scope_fingerprint": evaluation.scope_fingerprint,
        "event_set_fingerprint": evaluation.event_set_fingerprint,
        "context_fingerprint": evaluation.context_fingerprint,
        "context": run["context"].model_dump(mode="json"),
    }


def compare_runs(*, before: str | Path, after: str | Path) -> dict[str, Any]:
    """
    Compare two evaluation reports produced by ``aegis validate --format=json``.
    """
    before_report = _load_evaluation(before)
    after_report = _load_evaluation(after)
    return _compare_validated(before_report, after_report)


def compare_reports(*, before: dict, after: dict) -> dict[str, Any]:
    """Compare decoded reports in memory; never open evidence references."""
    return _compare_validated(validate_report(before), validate_report(after))


def _compare_validated(before_report, after_report):

    compatibility = (
        ("scenario_id", before_report["scenario_id"], after_report["scenario_id"]),
        ("scenario_version", before_report["scenario_version"], after_report["scenario_version"]),
        ("profile_id", before_report["profile_id"], after_report["profile_id"]),
        ("profile_version", before_report["profile_version"], after_report["profile_version"]),
        ("scenario_fingerprint", before_report["scenario_fingerprint"], after_report["scenario_fingerprint"]),
        ("profile_fingerprint", before_report["profile_fingerprint"], after_report["profile_fingerprint"]),
    )
    for field, before_value, after_value in compatibility:
        if before_value != after_value:
            _comparison_error(code="comparison_incompatible", field=field)

    before_context, after_context = before_report["context"], after_report["context"]
    if before_context.environment_id != after_context.environment_id:
        _comparison_error(field="environment_id")
    if {b.name: b.value for b in before_context.bindings} != {b.name: b.value for b in after_context.bindings}:
        _comparison_error(field="bindings")
    if before_context.end.difference_ns(before_context.start) != after_context.end.difference_ns(after_context.start):
        _comparison_error(field="window_duration")

    comparison_assertions, counts, total = _assertions_payload(before_report, after_report)
    status = _state_status(counts)

    return {
        "cli_report_version": "0.1.0",
        "kind": COMPARISON_KIND,
        "scenario": {
            "id": before_report["scenario_id"],
            "name": before_report["scenario_name"],
            "version": before_report["scenario_version"],
        },
        "before": _run_payload(before_report),
        "after": _run_payload(after_report),
        "comparison": {
            "assertion_count": total,
            "assertion_state_counts": {
                "unchanged_pass": counts["unchanged_pass"],
                "unchanged_fail": counts["unchanged_fail"],
                "improvement": counts["improvement"],
                "regression": counts["regression"],
                "unchanged_unknown": counts["unchanged_unknown"],
                "unknown_changed": counts["unknown_changed"],
                "became_evaluable": counts["became_evaluable"],
                "became_unevaluable": counts["became_unevaluable"],
            },
            "status": status,
            "assertions": comparison_assertions,
        },
    }
