"""Explicit offline collection review, separate from native lab verification."""

from typing import Literal

from pydantic import StrictBool

from ..intake import decode_config, local_path
from ..intake.io import MAX_CONFIG_BYTES
from ..models import PreciseTimestamp
from ..scenario_loader import parse_scenario_yaml
from ..validation import EvaluationContext, EvaluationProfile, evaluate_scenario
from ..validation.contracts import Digest, NonBlank
from ._bundle_io import read_file, strict_path
from ._bundle_render import config_bytes, digest
from ._study_contracts import Closed
from .run import verify_run
from .snapshot_bundle import verify_snapshot_bundle
from .study import FAILURES


class _Approval(Closed):
    kind: Literal['scn001_collection_approval']
    version: Literal['0.1.0']
    request_sha256: Digest
    confirmed_by: NonBlank
    reference: NonBlank
    collected_at: PreciseTimestamp
    reviewed_at: PreciseTimestamp
    coverage_start: PreciseTimestamp
    coverage_end: PreciseTimestamp
    no_sampling_or_truncation: StrictBool
    no_parse_errors_or_gaps: StrictBool
    clocks_adequate: StrictBool
    health_reference: NonBlank
    filter_reference: NonBlank
    rotation_reference: NonBlank
    backlog_reference: NonBlank
    native_reference: NonBlank
    time_reference: NonBlank


_CONFIRMATIONS = ('no_sampling_or_truncation', 'no_parse_errors_or_gaps', 'clocks_adequate')
_ERRORS = FAILURES + (OSError,)


class CollectionReviewError(ValueError):
    def __init__(self):
        super().__init__('invalid_collection_review')


def _review_inputs(bundle, run_inputs):
    if type(run_inputs) is not dict:
        raise CollectionReviewError()
    checked = verify_run(**run_inputs)
    root = local_path(strict_path(bundle), directory=True)
    completion = read_file(root / 'snapshot-bundle.json', MAX_CONFIG_BYTES)
    result = verify_snapshot_bundle(root)
    profile_bytes = read_file(root / 'profile.json', MAX_CONFIG_BYTES)
    context_bytes = read_file(root / 'context.json', MAX_CONFIG_BYTES)
    manifest = decode_config(completion, stage='inputs')
    # Pin the same payloads that verification checked. Owned immutable directory
    # remains required; this is not protection from a privileged concurrent writer.
    if (completion != read_file(root / 'snapshot-bundle.json', MAX_CONFIG_BYTES)
            or digest(profile_bytes) != manifest['files']['profile.json']
            or digest(context_bytes) != manifest['files']['context.json']
            or profile_bytes != run_inputs['profile']):
        raise CollectionReviewError()
    context = EvaluationContext.model_validate(decode_config(context_bytes, stage='context'))
    bindings = {item.name: item.value for item in checked.context.bindings}
    if (context != checked.context or manifest['scope']['agent_id'] != bindings['target_agent']
            or manifest['scope']['hostname'] != bindings['target_host']):
        raise CollectionReviewError()
    # scope.ingested_at is the caller's declaration of when this manager snapshot
    # was captured. It is not machine-verified and it does not show that any alert
    # had been indexed. It only rules out the provable case: a snapshot captured
    # before the run window closed cannot cover that window, so it must never
    # support complete_for_scope. Everything else stays the operator's judgement.
    ingested_at = PreciseTimestamp.parse(manifest['scope']['ingested_at'])
    if ingested_at < context.end:
        raise CollectionReviewError()
    scenario = parse_scenario_yaml(run_inputs['scenario'].decode('utf-8-sig'), source_name='study')
    profile = EvaluationProfile.model_validate(decode_config(profile_bytes, stage='profile'))
    events = tuple(document.telemetry.event for document in result.documents)
    evaluation = evaluate_scenario(scenario, events, profile=profile, context=context)
    request = config_bytes(dict(
        kind='scn001_collection_request', version='0.1.0', run_id=context.run_id,
        run_label=checked.run_label, assertion_id='SCN-001-A03', study_sha256=checked.study_sha256,
        run_input_sha256=dict(checked.input_sha256), bundle_sha256=digest(completion),
        profile_fingerprint=evaluation.profile_fingerprint, scope_fingerprint=evaluation.scope_fingerprint,
        event_set_fingerprint=evaluation.event_set_fingerprint,
        snapshot_ingested_at=ingested_at.isoformat(),
        coverage_start=context.start.isoformat(), coverage_end=context.end.isoformat()))
    return request, context, scenario, profile, events


def prepare_collection_request(bundle, *, run_inputs):
    """Read-only request, with no collection confirmations filled by the tool."""
    try:
        return _review_inputs(bundle, run_inputs)[0]
    except _ERRORS:
        raise CollectionReviewError() from None


def approve_collection_request(bundle, *, run_inputs, request, approval):
    """Return a new caller-attested context; never claim native lab verification.

    Preserve request and approval bytes alongside the returned context. References
    are declarations, not dereferenced files or authenticated remote evidence.
    """
    try:
        if type(request) is not bytes or len(request) > MAX_CONFIG_BYTES:
            raise CollectionReviewError()
        approved = _Approval.model_validate(decode_config(approval, stage='inputs'))
        if approved.request_sha256 != digest(request) or any(getattr(approved, k) is not True for k in _CONFIRMATIONS):
            raise CollectionReviewError()
        expected, context, scenario, profile, events = _review_inputs(bundle, run_inputs)
        if (request != expected or approved.coverage_start > context.start or approved.coverage_end < context.end
                or not approved.coverage_end <= approved.collected_at <= approved.reviewed_at):
            raise CollectionReviewError()
        data = decode_config(expected, stage='inputs')
        # The operator cannot have collected this evidence before the snapshot it
        # is approving was captured. The request pins that snapshot, so an approval
        # can never be carried across to a different or re-taken snapshot.
        if approved.collected_at < PreciseTimestamp.parse(data['snapshot_ingested_at']):
            raise CollectionReviewError()
        declaration = dict(assertion_id='SCN-001-A03', status='complete_for_scope',
                           confirmed_by=approved.confirmed_by, reference=approved.reference,
                           coverage_start=approved.coverage_start.isoformat(), coverage_end=approved.coverage_end.isoformat(),
                           **{k: getattr(approved, k) for k in _CONFIRMATIONS},
                           **{k: data[k] for k in ('profile_fingerprint', 'scope_fingerprint', 'event_set_fingerprint')})
        attested = EvaluationContext.model_validate(context.model_dump(mode='json') | {'declarations': [declaration]})
        evaluate_scenario(scenario, events, profile=profile, context=attested)  # Validate existing engine contract.
        return config_bytes(attested.model_dump(mode='json'))
    except _ERRORS:
        raise CollectionReviewError() from None
