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


class RunBindingError(ValueError):
    def __init__(self):
        super().__init__('invalid_run_binding')


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
                unknown.add('missing_binding_metadata')
            if event.process_id is None:
                unknown.add('missing_binding_metadata')
            elif event.process_id != final['child_pid']:
                conflicts.add('child_pid_mismatch')
            if not launch <= event.timestamp <= exit_time:
                conflicts.add('outside_execution_interval')
            expected = target['command_lines'][variant] if parser == 'wazuh-sysmon1-v1' else target['canonical_paths'][variant]
            actual = event.command_line if parser == 'wazuh-sysmon1-v1' else event.file_path
            if truth is Truth.FALSE or (actual is not None and actual != expected):
                conflicts.add('payload_variant_mismatch')
            required = [provenance.windows_record_id]
            if parser == 'wazuh-sysmon1-v1':
                required += [provenance.process_guid, provenance.parent_process_id]
                if provenance.parent_process_id is not None and provenance.parent_process_id != final['runner_pid']:
                    conflicts.add('parent_pid_mismatch')
            else:
                required += [provenance.script_block_id, provenance.message_number, provenance.message_total]
            if any(v is None or (isinstance(v, str) and not v.strip()) for v in required):
                unknown.add('missing_binding_metadata')
        if not group:
            unknown.add('missing_telemetry')
        elif len(group) > 1:
            conflicts.add('multiple_candidates')
        selected.extend(group)
    return selected, conflicts, unknown


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
            if len(selected) == 2 and len({d.parser for d in selected}) == 2:
                consistent, native_unknown = _native_matches(receipt, selected)
                unknown |= native_unknown
                if not consistent:
                    conflicts.add('native_metadata_mismatch')
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
