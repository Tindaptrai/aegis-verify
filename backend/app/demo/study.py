"""Pin SCN-001 study, reviewed profile and kit bytes without changing them."""

from hashlib import sha256
import re

from pydantic import ValidationError

from ..intake import decode_config, IntakeError
from ..intake.io import _bundle_relative, _path_text
from ..scenario_loader import parse_scenario_yaml, ScenarioLoadError
from ..validation import EvaluationProfile, scenario_fingerprint
from ._study_contracts import Study, StudyRunError


PAYLOAD = b"$facts = @{ Host = $env:COMPUTERNAME; User = $env:USERNAME; Pid = $PID }\nWrite-Output 'AEGIS_SAFE_DEMO_V1'\nWrite-Output ('AEGIS_PID=' + $facts.Pid)\n"
FILENAMES = ('lab_update.ps1', 'maintenance_check.ps1')
_CASES = ('comment-only', 'env-only', 'fragmented', 'marker-only', 'missing-counter', 'missing-text',
          'original', 'pid-only', 'renamed', 'reworded', 'unrelated', 'wrong-channel', 'wrong-event-id',
          'wrong-host', 'wrong-provider')
_ARTIFACTS = frozenset((*FILENAMES, 'baseline.xml', 'fixed.xml', 'behavioral.xml', 'Invoke-SafeDemo.ps1',
                       'logtest-cases/catalog.json', *(f'logtest-cases/{name}.synthetic.json' for name in _CASES)))
_KIT_KEYS = frozenset(('kind', 'kit_version', 'scenario_id', 'scenario_version', 'target_host', 'lab_directory',
                       'filenames', 'rule_id', 'parent_sid', 'field_profile', 'occupied_ids_declared',
                       'payload_sha256', 'artifact_sha256'))
FAILURES = (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError,
            ValidationError, IntakeError, ScenarioLoadError)


def digest(raw):
    if type(raw) is not bytes:
        raise StudyRunError()
    return sha256(raw).hexdigest()


def same(actual, expected):
    return type(actual) is type(expected) and actual == expected


def _profile_rules(target):
    base = [{'field': 'hostname', 'op': 'eq', 'binding': 'target_host'},
            {'field': 'asset_id', 'op': 'eq', 'binding': 'target_agent'}]
    ps = base + [{'field': 'event_provider', 'op': 'eq', 'value': 'Microsoft-Windows-PowerShell'}]
    sysmon = base + [{'field': 'event_provider', 'op': 'eq', 'value': 'Microsoft-Windows-Sysmon'}]
    path = {'field': 'file_path', 'op': 'in', 'values': list(target.canonical_paths)}
    return [
        dict(assertion_id='SCN-001-A01', role='telemetry', capability='supported', source_type='wazuh',
             scope=sysmon, match=[{'field': 'process_name', 'op': 'eq', 'value': target.canonical_executable},
                                  {'field': 'command_line', 'op': 'in', 'values': list(target.command_lines)}]),
        dict(assertion_id='SCN-001-A02', role='telemetry', capability='supported', source_type='wazuh',
             scope=ps, match=[path]),
        # A manager archive record carries a rule block only when something
        # matched it, so an absent one says no rule fired rather than leaving the
        # question open. Without this the run's own PowerShell defeats the
        # assertion: it emits script blocks for text that came from no file, and
        # those carry neither path nor rule, so every condition here reads
        # unknown and an absence can never be concluded. Keeping the equality
        # below means a rule that did fire is still compared by its id.
        dict(assertion_id='SCN-001-A03', role='detection', capability='supported', source_type='wazuh',
             scope=ps, match=[path, {'field': 'rule_id', 'op': 'exists'},
                              {'field': 'rule_id', 'op': 'eq', 'value': str(target.rule_id)}],
             correlation=dict(anchor_assertion_id='SCN-001-A01',
                              join_pairs=[dict(target_field=k, anchor_field=k) for k in ('hostname', 'asset_id', 'process_id')],
                              min_delta_ns=-5000000000, max_delta_ns=15000000000)),
    ]


def verify_study(study, *, study_sha256, scenario, profile, kit, artifacts):
    """Require an independently pinned study hash; does not authenticate the pin."""
    try:
        if digest(study) != study_sha256:
            raise StudyRunError()
        reviewed = Study.model_validate(decode_config(study, stage='inputs'))
        target, pins = reviewed.target, reviewed.pins
        for raw, expected in ((scenario, pins.scenario), (profile, pins.profile), (kit, pins.kit)):
            if digest(raw) != expected:
                raise StudyRunError()
        for path in (target.native_directory, target.executable):
            _path_text(path, stage='inputs')
            if not re.fullmatch(r'[A-Za-z]:\\[^\r\n]+', path) or any(p in {'.', '..'} for p in path.split('\\')):
                raise StudyRunError()
        manifest = parse_scenario_yaml(scenario.decode('utf-8'), source_name='<reviewed-scenario>')
        if (manifest.id != 'SCN-001' or manifest.version != '0.1.0'
                or manifest.expected_outcome != 'detected'
                or [(a.id, a.source) for a in manifest.assertions] != [
                    ('SCN-001-A01', 'sysmon'), ('SCN-001-A02', 'powershell'), ('SCN-001-A03', 'wazuh')]):
            raise StudyRunError()
        parsed_profile = EvaluationProfile.model_validate(decode_config(profile, stage='profile'))
        expected_profile = parsed_profile.model_dump(mode='json') | {
            'scenario_id': 'SCN-001', 'scenario_version': '0.1.0',
            'scenario_fingerprint': scenario_fingerprint(manifest), 'rules': _profile_rules(target)}
        if parsed_profile != EvaluationProfile.model_validate(expected_profile):
            raise StudyRunError()
        kit_data = decode_config(kit, stage='inputs')
        if set(kit_data) != _KIT_KEYS or type(artifacts) is not dict or set(artifacts) != _ARTIFACTS:
            raise StudyRunError()
        # 0.2.0 is the v2 lab set; 0.3.0 adds the runner exception (issue #91). The pins decide the bytes.
        if not same(kit_data.get('kit_version'), '0.2.0') and not same(kit_data.get('kit_version'), '0.3.0'):
            raise StudyRunError()
        expected = dict(kind='safe_demo_kit', scenario_id='SCN-001', scenario_version='0.1.0',
                        target_host=target.hostname, lab_directory=target.native_directory, filenames=list(FILENAMES),
                        rule_id=target.rule_id, parent_sid=target.parent_sid, field_profile=target.field_profile,
                        payload_sha256=pins.payload)
        if any(not same(kit_data.get(k), v) for k, v in expected.items()):
            raise StudyRunError()
        occupied = kit_data['occupied_ids_declared']
        if (type(occupied) is not list or any(type(x) is not int or not 1 <= x <= 999999 for x in occupied)
                or len(set(occupied)) != len(occupied) or target.rule_id in occupied):
            raise StudyRunError()
        artifact_hashes = kit_data['artifact_sha256']
        if type(artifact_hashes) is not dict or set(artifact_hashes) != _ARTIFACTS:
            raise StudyRunError()
        for name, raw in artifacts.items():
            _bundle_relative(name, stage='inputs')
            if type(raw) is not bytes or len(raw) > 65536 or digest(raw) != artifact_hashes[name]:
                raise StudyRunError()
        if any(artifacts[name] != PAYLOAD for name in FILENAMES):
            raise StudyRunError()
        for name, pin in (('Invoke-SafeDemo.ps1', pins.runner), ('baseline.xml', pins.baseline),
                          ('fixed.xml', pins.fixed), ('behavioral.xml', pins.behavioral),
                          ('lab_update.ps1', pins.payload)):
            if digest(artifacts[name]) != pin:
                raise StudyRunError()
        return reviewed
    except FAILURES:
        raise StudyRunError() from None
