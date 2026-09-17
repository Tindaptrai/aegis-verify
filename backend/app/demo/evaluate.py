"""Bridge a reviewed run and its transport to the existing evaluation report.

This module only orchestrates checks that already exist. It never executes the
payload, never reads a live manager, never writes an attestation and never
derives a verdict of its own. Comparison stays with ``aegis_verify.compare``.
"""

from .._scenario_yaml import MAX_BYTES as MAX_SCENARIO_BYTES
from ..cli.service import evaluate_bundle
from ..compare import compare_reports
from ..intake import decode_config, local_path
from ..intake.io import MAX_CONFIG_BYTES
from ..validation import EvaluationContext
from ._bundle_io import read_file, strict_path
from ._bundle_render import digest
from .collection_review import approve_collection_request, prepare_collection_request
from .run import verify_run
from .run_binding import review_run_binding
from .snapshot_bundle import verify_snapshot_bundle
from .study import FAILURES


class DemoEvaluationError(ValueError):
    """Sanitized diagnostic; never includes source bytes, paths or config values."""

    def __init__(self):
        super().__init__('invalid_demo_evaluation')


_ERRORS = FAILURES + (OSError,)
_DECLARABLE = 'SCN-001-A03'


def _context(raw, stage):
    return EvaluationContext.model_validate(decode_config(raw, stage=stage))


def _attested(raw, checked, *, bundle, run_inputs, request, approval):
    """Accept an attested context only if the review that produced it is reproduced.

    Equality with the verified context is not enough on its own: it would let a
    hand-authored declaration carry collection assurance without ever passing the
    approval gates. So the request and the operator approval are required, the
    review is re-run here, and the result must match the supplied bytes exactly.
    That binds the assurance to this run, this study and this snapshot.

    Re-running the review does not make the approval evidence of complete
    collection. It stays a caller attestation; this only checks it was actually
    made, for these inputs.
    """
    if not (type(request) is bytes and type(approval) is bytes):
        raise DemoEvaluationError()
    if approve_collection_request(bundle, run_inputs=run_inputs, request=request, approval=approval) != raw:
        raise DemoEvaluationError()

    context = _context(raw, 'context')
    unknown = context.model_dump(mode='json') | {'declarations': []}
    if unknown != checked.context.model_dump(mode='json'):
        raise DemoEvaluationError()
    if any(item.assertion_id != _DECLARABLE for item in context.declarations):
        raise DemoEvaluationError()
    return context


def evaluate_demo_run(bundle, *, run_inputs, scenario, context=None, request=None, approval=None):
    """Evaluate one reviewed SCN-001 run and return the standard CLI report.

    ``context`` is an optional path to a context produced by
    ``approve_collection_request``. Without it the run is evaluated with unknown
    collection assurance, which is the correct default: absent alerts then stay
    Inconclusive instead of becoming a false negative.

    Passing ``context`` requires ``request`` and ``approval`` bytes as well. The
    review is re-run from them and must reproduce the context exactly, so an
    attested context cannot reach this path without having gone through the
    collection review for this run, study and snapshot.
    """
    try:
        if type(run_inputs) is not dict:
            raise DemoEvaluationError()
        checked = verify_run(**run_inputs)
        root = local_path(strict_path(bundle), directory=True)
        verify_snapshot_bundle(root)

        # The transport must carry the same reviewed profile and the same
        # unknown-assurance context that run verification derived.
        profile_raw = read_file(root / 'profile.json', MAX_CONFIG_BYTES)
        if profile_raw != run_inputs['profile']:
            raise DemoEvaluationError()
        context_raw = read_file(root / 'context.json', MAX_CONFIG_BYTES)
        if _context(context_raw, 'context') != checked.context:
            raise DemoEvaluationError()
        scenario_raw = read_file(strict_path(scenario), MAX_SCENARIO_BYTES)
        if scenario_raw != run_inputs['scenario']:
            raise DemoEvaluationError()

        review = None
        if context is not None:
            context_raw = read_file(strict_path(context), MAX_CONFIG_BYTES)
            _attested(context_raw, checked, bundle=bundle, run_inputs=run_inputs,
                      request=request, approval=approval)
            # The attested context is the one input that turns an absent alert
            # into a false negative. Record which review produced it, so a reader
            # can see an approval was required and which one it was.
            review = dict(request_sha256=digest(request), approval_sha256=digest(approval),
                          assurance='caller-attested')
        elif request is not None or approval is not None:
            raise DemoEvaluationError()

        report = evaluate_bundle(scenario, root, context=context)

        # evaluate_bundle re-reads every input independently. Reconcile its
        # fingerprints with the bytes checked above, so the report cannot
        # describe a profile, scenario or attested context other than the
        # reviewed one. The attested context matters most: it is the single
        # input that turns an absent alert into a false negative, and it lives
        # outside the owned immutable bundle directory.
        fingerprints = report['input_fingerprints']
        if (fingerprints['profile'] != digest(profile_raw)
                or fingerprints['scenario'] != digest(scenario_raw)
                or fingerprints['context'] != digest(context_raw)
                or fingerprints['inputs'] != digest(read_file(root / 'inputs.json', MAX_CONFIG_BYTES))):
            raise DemoEvaluationError()
        if report['evaluation']['run_id'] != checked.context.run_id:
            raise DemoEvaluationError()

        # The profile deliberately accepts either reviewed payload variant, so the
        # evaluation alone cannot tell one run's telemetry from another's. Only run
        # binding can. Refuse a conflicting binding outright, and attach the result
        # otherwise so nobody reads a verdict without it. native_review is not
        # passed: a caller-declared "reviewed" flag is not evidence, so the status
        # here never reaches caller_reviewed and always carries its reasons.
        binding = decode_config(review_run_binding(bundle, run_inputs=run_inputs), stage='inputs')
        if binding['status'] == 'conflict' or binding['request_sha256'] != digest(
                prepare_collection_request(bundle, run_inputs=run_inputs)):
            raise DemoEvaluationError()
        report['run_binding'] = binding
        report['collection_review'] = review
        return report
    except _ERRORS:
        raise DemoEvaluationError() from None


def compare_demo_runs(*, before, after):
    """Compare two demo reports and keep both run-binding results beside the verdict.

    The comparison verdict is produced by the existing engine contract and is not
    altered here. What is added is context a reader needs: `Regression Passed` on
    its own says nothing about how well each run was bound to its evidence, and
    the binding result lives in the evaluation report, one hop upstream. Carrying
    it forward means the limits of each run travel with the conclusion.

    Both reports must come from `evaluate_demo_run`, so a report that never had a
    binding checked cannot be compared through this path.
    """
    try:
        if type(before) is not dict or type(after) is not dict:
            raise DemoEvaluationError()
        bindings = {}
        for side, report in (('before', before), ('after', after)):
            binding = report.get('run_binding')
            if type(binding) is not dict or binding.get('kind') != 'scn001_run_binding':
                raise DemoEvaluationError()
            # Bind the attachment to the report it decorates. Without this a
            # binding could be swapped between reports, or replaced by one
            # claiming caller_reviewed, and be copied into the output verbatim.
            evaluation = report.get('evaluation')
            if type(evaluation) is not dict or binding.get('run_id') != evaluation.get('run_id'):
                raise DemoEvaluationError()
            if binding.get('both_sides_caller_declared') is not True:
                raise DemoEvaluationError()
            bindings[side] = binding

        comparison = compare_reports(before=before, after=after)
        comparison['run_binding'] = {
            side: {key: bindings[side][key] for key in
                   ('run_id', 'status', 'reasons', 'both_sides_caller_declared',
                    'request_sha256', 'native_review_sha256')}
            for side in ('before', 'after')}
        return comparison
    except _ERRORS:
        raise DemoEvaluationError() from None
