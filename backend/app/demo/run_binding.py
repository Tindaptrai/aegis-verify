"""Read-only run binding inspection; never substitutes for a detection verdict."""

from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt

from ..intake import decode_config
from ..models import PreciseTimestamp
from ..validation.contracts import Digest, NonBlank
from ..validation.predicates import Truth, evaluate_conditions
from ._study_contracts import Closed
from ._execution_json import decode_execution
from ._bundle_render import config_bytes, digest
from .collection_review import _review_inputs
from .snapshot_bundle import verify_snapshot_bundle
from .study import FAILURES


class _NativeRecord(Closed):
    evidence_id: NonBlank
    hostname: NonBlank
    provider: NonBlank
    windows_record_id: NonBlank
    event_time: PreciseTimestamp
    process_id: Annotated[StrictInt, Field(ge=1, le=4294967295)]
    process_guid: NonBlank | None
    script_block_id: NonBlank | None
    # Optional so existing reviews stay valid. Supplying it lets an operator
    # reading the EVTX corroborate the parent chain, which is the one relation
    # nothing else here can check. Leaving it out is recorded, never assumed.
    parent_process_id: Annotated[StrictInt, Field(ge=1, le=4294967295)] | None = None


class _NativeReview(Closed):
    kind: Literal['scn001_native_review']
    version: Literal['0.1.0']
    request_sha256: Digest
    confirmed_by: NonBlank
    reference: NonBlank
    reviewed_at: PreciseTimestamp
    payload_path: NonBlank
    payload_sha256: Digest
    full_script_reviewed: StrictBool
    records: Annotated[list[_NativeRecord], Field(min_length=2, max_length=2)]


# How far a companion script block may trail exit_observed_utc and still be read
# as the child's own shutdown record. The timestamp that trails is the event's
# systemTime, stamped by PowerShell as it logs the shutdown block; the one it
# trails is exit_observed_utc, stamped by the runner when it saw the child go.
# Those are two clocks on one host reading one moment from either side of it, so
# a few milliseconds either way is the expected shape, not an anomaly. Measured
# on real runs: -0.5 ms, +2.3 ms, -87 ms. The bound is deliberately far above
# that and finite: past it a record is no longer explained by the exit race.
COMPANION_EXIT_GRACE_NS = 1_000_000_000


class RunBindingError(ValueError):
    def __init__(self):
        super().__init__('invalid_run_binding')


def _blank(value):
    return value is None or (isinstance(value, str) and not value.strip())


def _provenance_required(doc):
    """The provenance a document must carry to be looked up in the EVTX at all."""
    provenance = doc.telemetry.provenance
    if doc.parser == 'wazuh-sysmon1-v1':
        return [provenance.windows_record_id, provenance.process_guid, provenance.parent_process_id]
    return [provenance.windows_record_id, provenance.script_block_id,
            provenance.message_number, provenance.message_total]


def _companion_shape(doc, final):
    """A script block the bound process emitted for text that came from no file.

    Shape only. Whether it may actually fill the role is decided in `_roles`,
    which also requires the provenance an operator would need to find it.
    """
    return (doc.parser == 'wazuh-powershell4104-v1'
            and doc.telemetry.event.file_path is None
            and doc.telemetry.event.process_id == final['child_pid'])


def _candidates(documents, profile, context, final, target):
    conflicts, unknown, selected = set(), set(), []
    bindings = {item.name: item.value for item in context.bindings}
    launch = PreciseTimestamp.parse(final['launch_utc'])
    exit_time = PreciseTimestamp.parse(final['exit_observed_utc'])
    variant = 0 if final['run_label'] == 'A' else 1
    for rule, parser in zip(profile.rules[:2], ('wazuh-sysmon1-v1', 'wazuh-powershell4104-v1')):
        group = []
        for doc in documents:
            if doc.parser != parser:
                continue
            event, provenance = doc.telemetry.event, doc.telemetry.provenance
            truth = evaluate_conditions(event, rule.scope + rule.match, bindings)
            if truth is Truth.FALSE and event.process_id != final['child_pid']:
                continue
            group.append(doc)
            if truth is Truth.UNKNOWN:
                # A companion carries no path by nature, so the rule's condition
                # cannot be decided for it. Saying that in its own words keeps it
                # from reading as a bound record whose metadata went missing.
                unknown.add('companion_record_unmatched' if _companion_shape(doc, final)
                            else 'missing_binding_metadata')
            if event.process_id is None:
                unknown.add('missing_binding_metadata')
            elif event.process_id != final['child_pid']:
                conflicts.add('child_pid_mismatch')
            if not launch <= event.timestamp <= exit_time:
                # Only a companion of the bound child gets the grace, only after
                # exit, only within the bound, and it is recorded rather than
                # accepted silently. Bound records keep the strict interval, and a
                # late record from any other process stays a conflict.
                trailing_ns = event.timestamp.epoch_nanoseconds - exit_time.epoch_nanoseconds
                if _companion_shape(doc, final) and 0 < trailing_ns <= COMPANION_EXIT_GRACE_NS:
                    unknown.add('companion_after_exit')
                else:
                    conflicts.add('outside_execution_interval')
            expected = target['command_lines'][variant] if parser == 'wazuh-sysmon1-v1' else target['canonical_paths'][variant]
            actual = event.command_line if parser == 'wazuh-sysmon1-v1' else event.file_path
            if truth is Truth.FALSE or (actual is not None and actual != expected):
                conflicts.add('payload_variant_mismatch')
            if (parser == 'wazuh-sysmon1-v1' and provenance.parent_process_id is not None
                    and provenance.parent_process_id != final['runner_pid']):
                conflicts.add('parent_pid_mismatch')
            if any(_blank(value) for value in _provenance_required(doc)):
                unknown.add('missing_binding_metadata')
        if not group:
            unknown.add('missing_telemetry')
        selected.extend(group)
    return selected, conflicts, unknown


def _roles(selected, final):
    """Say which document each parser's receipt entry describes.

    A receipt names one event per parser: the process-create event for the run's
    own child, and the script block carrying the payload's path. Those are the
    two the operator can look up in the EVTX, so those are the two compared.

    A process emits more than one script block. Measured across the lab runs,
    each produced one for the payload file and one for script text that came
    from no file and so carries no path at all. The second is the same child
    speaking again, so it is kept as evidence and named a companion rather than
    read as a rival answer to which launch this is.

    A companion still has to be findable: without the record number and script
    block id an operator cannot look it up, so it cannot be vouched for and does
    not fill the role. Anything that fills neither role leaves the parser
    unresolved, and the caller fails closed, because nothing here can say which
    record the receipt meant.

    Returns (bound, companions, reasons); a non-empty `reasons` is a conflict.
    """
    bound, companions, reasons = {}, [], set()
    for parser in ('wazuh-sysmon1-v1', 'wazuh-powershell4104-v1'):
        group = [doc for doc in selected if doc.parser == parser]
        if not group:
            continue
        if parser == 'wazuh-sysmon1-v1':
            named, kin = group, []
        else:
            named = [doc for doc in group if doc.telemetry.event.file_path is not None]
            kin = [doc for doc in group if _companion_shape(doc, final)
                   and not any(_blank(value) for value in _provenance_required(doc))]
        # Every document must be accounted for, or the split is a guess. Name the
        # failure found: nothing to bind to reads differently from too much.
        if len(named) == 1 and len(named) + len(kin) == len(group):
            bound[parser] = named[0]
            companions.extend(kin)
        elif not named:
            reasons.add('bound_record_unidentified')
        else:
            reasons.add('multiple_candidates')
    return bound, companions, reasons


def _native_matches(receipt, documents):
    """Compare two caller-authored documents. Returns (consistent, unknown reasons).

    Both sides are supplied by the caller, so agreement means only that the
    caller's own files agree. Any field that cannot be compared is reported,
    never treated as a completed binding.
    """
    unknown, consistent = set(), True
    records = {r.evidence_id: r for r in receipt.records}
    if len(records) != 2 or set(records) != {d.telemetry.event.event_id for d in documents}:
        return False, unknown
    for doc in documents:
        event, provenance = doc.telemetry.event, doc.telemetry.provenance
        provided = records[event.event_id]
        pairs = dict(hostname=event.hostname, provider=event.event_provider,
                     windows_record_id=provenance.windows_record_id, event_time=event.timestamp,
                     process_id=event.process_id)
        if doc.parser == 'wazuh-sysmon1-v1':
            pairs['process_guid'] = provenance.process_guid
            pairs['parent_process_id'] = provenance.parent_process_id
            if provided.script_block_id is not None:
                consistent = False
                continue
        else:
            pairs['script_block_id'] = provenance.script_block_id
            if provided.process_guid is not None or provided.parent_process_id is not None:
                consistent = False
                continue
        # Keep scanning after a mismatch: conflict already decides the status, but
        # the reasons list must still name every field that could not be compared.
        for key, value in pairs.items():
            # Missing source metadata must stay unknown, never filled from receipt,
            # and never silently skipped as if the field had been corroborated.
            if value is None or (isinstance(value, str) and not value.strip()):
                unknown.add('missing_binding_metadata')
                continue
            if key == 'parent_process_id' and getattr(provided, key) is None:
                unknown.add('native_parent_unconfirmed')
                continue
            if getattr(provided, key) != value:
                consistent = False
    return consistent, unknown


def review_run_binding(bundle, *, run_inputs, native_review=None):
    """Compare canonical/provenance binding and operator-native declarations.

    caller_reviewed means only consistent with supplied declarations, not that
    original EVTX bytes, collection completeness or a detection were verified.
    """
    try:
        request, context, _, profile, _ = _review_inputs(bundle, run_inputs)
        parsed = verify_snapshot_bundle(bundle)
        if _review_inputs(bundle, run_inputs)[0] != request:
            raise RunBindingError()
        final = decode_execution(run_inputs['execution'])
        study = decode_config(run_inputs['study'], stage='inputs')
        selected, conflicts, unknown = _candidates(parsed.documents, profile, context, final, study['target'])
        bound, companions, role_conflicts = _roles(selected, final)
        conflicts |= role_conflicts
        # One shutdown block per run is the measured shape. More than one is
        # still the child speaking, so it does not fail closed, but it is not
        # the shape that was measured and must not pass in silence.
        if len(companions) > 1:
            unknown.add('multiple_companions')
        if native_review is None:
            unknown.add('native_review_missing')
        else:
            receipt = _NativeReview.model_validate(decode_config(native_review, stage='inputs'))
            if receipt.request_sha256 != digest(request) or receipt.reviewed_at < PreciseTimestamp.parse(final['window_observed_end_utc']):
                raise RunBindingError()
            if not receipt.full_script_reviewed:
                unknown.add('native_content_unconfirmed')
            if receipt.payload_path != final['payload_path'] or receipt.payload_sha256 != study['pins']['payload']:
                conflicts.add('native_payload_mismatch')
            # The comparison runs on the documents the receipt describes. It is
            # never skipped on a document count: when a role could not be filled
            # the run has already failed closed above, and the reason below says
            # the comparison could not be performed rather than leaving silence.
            if len(bound) == 2:
                consistent, native_unknown = _native_matches(receipt, tuple(bound.values()))
                unknown |= native_unknown
                if not consistent:
                    conflicts.add('native_metadata_mismatch')
            else:
                conflicts.add('native_comparison_unavailable')
        evidence = sorted((dict(event_id=d.telemetry.event.event_id, raw_event_ref=d.telemetry.event.raw_event_ref,
                                raw_event_hash=d.telemetry.event.raw_event_hash) for d in selected), key=lambda r: r['event_id'])
        return config_bytes(dict(kind='scn001_run_binding', version='0.1.0', run_id=context.run_id,
                                 request_sha256=digest(request), native_review_sha256=None if native_review is None else digest(native_review),
                                 status='conflict' if conflicts else 'unknown' if unknown else 'caller_reviewed',
                                 # Both compared sides are caller-authored files. This flag keeps
                                 # `caller_reviewed` from being read as independent verification.
                                 both_sides_caller_declared=True,
                                 reasons=sorted(conflicts | unknown), evidence=evidence))
    except FAILURES + (OSError,):
        raise RunBindingError() from None
