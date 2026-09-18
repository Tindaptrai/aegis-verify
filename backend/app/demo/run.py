"""Offline SCN-001 runner evidence checks, never execution or attestation."""


from dataclasses import dataclass
from decimal import Decimal
import re
from types import MappingProxyType

from ..models import PreciseTimestamp
from ..intake import decode_config
from ..validation import EvaluationContext
from ._study_contracts import RuleReceipt, StudyRunError
from ._execution_json import decode_execution
from .study import FAILURES, FILENAMES, digest, same, verify_study


@dataclass(frozen=True, slots=True)
class CheckedRun:
    context: EvaluationContext
    child_pid: int
    run_label: str
    study_sha256: str
    input_sha256: MappingProxyType


def _pid(value):
    if type(value) is not int or not 1 <= value <= 4294967295:
        raise StudyRunError()
    return value


def _stamp(value):
    if type(value) is not str:
        raise StudyRunError()
    return PreciseTimestamp.parse(value)


def _equal_record(actual, expected):
    if set(actual) != set(expected) or any(not same(actual[k], v) for k, v in expected.items()):
        raise StudyRunError()


def verify_run(*, study, study_sha256, scenario, profile, kit, artifacts,
               execution_start, execution_launched, execution, stdout, stderr, receipt):
    """Check pinned local declarations, not real host state or collection health."""
    try:
        reviewed = verify_study(study, study_sha256=study_sha256, scenario=scenario,
                                profile=profile, kit=kit, artifacts=artifacts)
        target = reviewed.target
        first, launched, final = (decode_execution(raw) for raw in (execution_start, execution_launched, execution))
        run_id, label = first.get('run_id'), first.get('run_label')
        if type(run_id) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', run_id) is None:
            raise StudyRunError()
        if type(label) is not str or label not in {'A', 'B', 'C', 'Rehearsal'}:
            raise StudyRunError()
        revision = first.get('applied_rule_revision_declared')
        # Run C applies the behavioral revision. The content-matching `fixed`
        # revision is still shipped and pinned, but no run label applies it.
        if (revision not in ('baseline', 'fixed', 'behavioral') or (label in {'A', 'B'} and revision != 'baseline')
                or (label == 'C' and revision != 'behavioral')):
            raise StudyRunError()
        rule_hash = getattr(reviewed.pins, revision)
        path = target.native_directory + '\\' + FILENAMES[0 if label == 'A' else 1]
        start = _stamp(first.get('window_start_utc'))
        planned = _stamp(first.get('window_planned_end_utc'))
        if planned.difference_ns(start) != 120000000000:
            raise StudyRunError()
        common = dict(kind='safe_demo_execution', execution_manifest_version='0.1.0', run_id=run_id, run_label=label,
                      target_host=target.hostname, scenario_id='SCN-001', scenario_version='0.1.0',
                      payload_sha256=reviewed.pins.payload, payload_path=path, rule_id=target.rule_id, parent_sid=target.parent_sid,
                      applied_rule_revision_declared=revision, applied_rule_sha256_declared=rule_hash,
                      rule_state_verified_remotely=False, runner_pid=_pid(first.get('runner_pid')),
                      executable=target.executable, arguments='-NoLogo -NoProfile -NonInteractive -File "' + path + '"',
                      window_start_utc=first['window_start_utc'], window_planned_end_utc=first['window_planned_end_utc'])
        stage = dict(child_pid=None, launch_utc=None, exit_observed_utc=None, window_observed_end_utc=None,
                     exit_code=None, timed_out=False, status='started', failure_code=None)
        _equal_record(first, common | stage)
        child = _pid(launched.get('child_pid'))
        launch = _stamp(launched.get('launch_utc'))
        if child == common['runner_pid']:
            raise StudyRunError()
        stage |= dict(child_pid=child, launch_utc=launched['launch_utc'])
        _equal_record(launched, common | stage)
        exit_time, observed = (_stamp(final.get(k)) for k in ('exit_observed_utc', 'window_observed_end_utc'))
        elapsed = final.get('elapsed_seconds')
        if type(elapsed) not in (int, Decimal) or not Decimal(elapsed).is_finite() or elapsed < 120:
            raise StudyRunError()
        if not start <= launch <= exit_time <= planned <= observed:
            raise StudyRunError()
        stage |= dict(exit_observed_utc=final['exit_observed_utc'], window_observed_end_utc=final['window_observed_end_utc'],
                      exit_code=0, status='executed', elapsed_seconds=elapsed)
        _equal_record(final, common | stage)
        expected_stdout = f'AEGIS_SAFE_DEMO_V1\nAEGIS_PID={child}\n'.encode('ascii')
        if type(stdout) is not bytes or stdout.replace(b'\r\n', b'\n') != expected_stdout or not same(stderr, b''):
            raise StudyRunError()
        declaration = RuleReceipt.model_validate(decode_config(receipt, stage='inputs'))
        if (declaration.run_id != run_id or declaration.study_sha256 != study_sha256
                or declaration.execution_sha256 != digest(execution) or declaration.account != target.account
                or declaration.elevated is not target.elevated or declaration.before_rule_sha256 != rule_hash
                or declaration.after_rule_sha256 != rule_hash or declaration.before_utc > start
                or declaration.after_utc < observed):
            raise StudyRunError()
        context = EvaluationContext.model_validate(dict(
            run_id=run_id, environment_id=target.environment_id, start=start, end=planned,
            bindings=[{'name': 'target_host', 'value': target.hostname}, {'name': 'target_agent', 'value': target.agent_id}],
            declarations=[]))
        hashes = {name: digest(raw) for name, raw in (
            ('study.json', study), ('execution-start.json', execution_start), ('execution-launched.json', execution_launched),
            ('execution.json', execution), ('stdout.txt', stdout), ('stderr.txt', stderr), ('rule-receipt.json', receipt))}
        return CheckedRun(context, child, label, study_sha256, MappingProxyType(hashes))
    except FAILURES:
        raise StudyRunError() from None
