"""Prepare a reviewed, local-only SCN-001 lab kit. Never execute its contents.

Parent rule and occupied IDs are operator inputs, not discovery or an attestation
of the manager's state. No AEGIS security verdict is produced by this utility.
"""

import argparse
import copy
import hashlib
import json
import re
import stat
import sys
from pathlib import Path
from string import Template
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b"$facts = @{ Host = $env:COMPUTERNAME; User = $env:USERNAME; Pid = $PID }\nWrite-Output 'AEGIS_SAFE_DEMO_V1'\nWrite-Output ('AEGIS_PID=' + $facts.Pid)\n"
FILENAMES = ('lab_update.ps1', 'maintenance_check.ps1')
REVISIONS = ('baseline', 'fixed', 'behavioral')
KIT_VERSION = '0.3.0'
# The behavioral revision is written from the two behaviors the scenario shows
# in one script block, never from the payload text: an environment or machine
# identity read, and a process identity read. Any wording of either counts, so
# renaming the file or rephrasing the script does not escape it, while a script
# that does only one of the two is left to the parent rules. It is deliberately
# not derived from PAYLOAD so the rule cannot quietly become content matching.
BEHAVIOR_PATTERN = (
    r'(?is)'
    r'(?=.*(?:\$env:(?:COMPUTERNAME|USERNAME|USERDOMAIN)\b'
    r'|\[Environment\]::(?:MachineName|UserName|UserDomainName)\b'
    r'|GetEnvironmentVariable))'
    r'(?=.*(?:\$PID\b|GetCurrentProcess\(\)\.Id\b))')
# The reviewed runner's preflight function reads the machine name and $PID to
# check where it runs, so it carries both behaviors and fired the rule in the v2
# lab set (issue #91). A level-0 child rule exempts it only at the runner's exact
# lab path and only for this function's own opening and error code.
RUNNER = 'Invoke-SafeDemo.ps1'
RUNNER_ANCHOR_PATTERN = r"(?s)\Afunction Get-AegisPreflight\s*\{.*'AEGIS_WRONG_HOST'"
# A second wording of the same two behaviors, used only as a synthetic control.
REWORDED = ("$m = [Environment]::MachineName; $u = [Environment]::UserName\n"
            "\"AEGIS_SAFE_DEMO_V1\"\n"
            "\"AEGIS_PID=\" + [System.Diagnostics.Process]::GetCurrentProcess().Id\n")
LEGACY_PROFILE = 'decoded-json-v1'
NATIVE_PROFILE = 'wazuh-eventchannel-4.14.4-lf-v1'


def _field_profile(value):
    if not isinstance(value, str) or value not in (LEGACY_PROFILE, NATIVE_PROFILE):
        raise ValueError('invalid_field_profile')


def _ids(rule_id, parent_sid):
    # rule_id + 1 is the behavioral revision's runner exception, so it must fit too.
    if type(rule_id) is not int or not 100000 <= rule_id <= 119999:
        raise ValueError('invalid_rule_id')
    if type(parent_sid) is not int or not 1 <= parent_sid <= 999999 or parent_sid == rule_id:
        raise ValueError('invalid_parent_sid')


def _host(host):
    if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}', host):
        raise ValueError('invalid_target_host')


def _directory(value):
    """Deliberately small Windows-path profile; reject instead of normalizing."""
    if not isinstance(value, str) or not 4 <= len(value) <= 200:
        raise ValueError('invalid_lab_directory')
    if not re.fullmatch(r'[A-Za-z]:\\[A-Za-z0-9 _\.\\-]+', value):
        raise ValueError('invalid_lab_directory')
    for part in value[3:].split('\\'):
        if (not part or part in ('.', '..') or part != part.strip()
                or part.endswith('.') or re.match(r'(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', part)):
            raise ValueError('invalid_lab_directory')
    return value


def _path_pattern(value):
    return r'\A' + re.escape(value) + r'\z'


def _asset(path):
    _no_links(path)
    if not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('invalid_kit_asset')
    return path.read_bytes()


def _no_links(path):
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('symlink_or_reparse_path')


def render_rule(*, revision: str, rule_id: int, parent_sid: int,
                target_host: str, baseline_path: str,
                field_profile: str = LEGACY_PROFILE) -> str:
    _field_profile(field_profile)
    _ids(rule_id, parent_sid)
    _host(target_host)
    if revision not in REVISIONS:
        raise ValueError('invalid_revision')
    if not isinstance(baseline_path, str) or not baseline_path.endswith('\\lab_update.ps1'):
        raise ValueError('invalid_baseline_path')
    _directory(baseline_path[:-len('\\lab_update.ps1')])
    runner_path = baseline_path[:-len('lab_update.ps1')] + RUNNER
    lines = PAYLOAD.decode('ascii').splitlines()
    script_pattern = r'\A' + r'\r?\n'.join(map(re.escape, lines)) + r'(?:\r?\n)?\z'
    content_description = 'reviewed script content matched'
    if field_profile == NATIVE_PROFILE:
        # Pinned, lossy EventChannel representation of THIS ASCII/LF payload.
        # Not a general Windows decoder or a reversible evidence normalization.
        baseline_path = baseline_path.replace('\\', '\\\\')
        runner_path = runner_path.replace('\\', '\\\\')
        script_pattern = _path_pattern(' '.join(lines))
        content_description = 'decoded script representation matched'
    template = _asset(ROOT / 'detections/wazuh/scn-001' / f'{revision}.xml.template')
    rendered = Template(template.decode('utf-8')).substitute(
        rule_id=str(rule_id), parent_sid=str(parent_sid), exception_rule_id=str(rule_id + 1),
        runner_path_pattern=escape(_path_pattern(runner_path)),
        runner_anchor_pattern=escape(RUNNER_ANCHOR_PATTERN),
        host_pattern=escape(_path_pattern(target_host)),
        path_pattern=escape(_path_pattern(baseline_path)),
        script_pattern=escape(script_pattern), content_description=content_description,
        behavior_pattern=escape(BEHAVIOR_PATTERN))
    if field_profile == NATIVE_PROFILE:
        rendered = f'<!-- Field profile: {NATIVE_PROFILE}; lossy decoded fields, not source bytes. -->\n' + rendered
    return rendered


def _output_directory(output_dir):
    if not isinstance(output_dir, Path) or not output_dir.is_absolute():
        raise ValueError('absolute_output_required')
    if str(output_dir).startswith(('\\\\', '//')):
        raise ValueError('local_output_required')
    if '..' in output_dir.parts or any(p.lower() in ('.git', 'raw-evidence') for p in output_dir.parts):
        raise ValueError('ambiguous_or_protected_output')
    # Kit contains environment bindings. Permit the ignored build area for tests,
    # but never generate into tracked repo areas or the ignored raw-fixture area.
    try:
        relative = output_dir.relative_to(ROOT)
    except ValueError:
        relative = None
    if relative is not None and (not relative.parts or relative.parts[0] != 'build'):
        raise ValueError('use_external_output_or_build')
    for parent in output_dir.parents:
        if (parent / '.git').exists():
            if parent != ROOT or relative is None or relative.parts[0] != 'build':
                raise ValueError('use_external_output_or_build')
            break
    _no_links(output_dir)
    if output_dir.exists() or not output_dir.parent.is_dir():
        raise ValueError('output_exists_or_parent_missing')
    return output_dir


def _synthetic_cases(target_host, lab_directory, field_profile):
    """Parameterize a committed test fixture; never read or generate lab evidence."""
    base = json.loads(_asset(ROOT / 'tests/fixtures/demo/scn-001/rule-cases/base.synthetic.json'))
    base['win']['system']['computer'] = target_host
    base['win']['eventdata']['path'] = lab_directory + '\\' + FILENAMES[0]
    # The 'original' case is the reviewed payload by definition, so take it from
    # PAYLOAD rather than trusting the fixture file to have been kept in step.
    base['win']['eventdata']['scriptBlockText'] = PAYLOAD.decode('ascii')
    # Columns: name, field, value, expected_baseline, expected_fixed, expected_behavioral.
    # 'parent_dependent' marks a baseline expectation that turns on whether the
    # operator's parent rule lets the record reach the demo rule at all.
    old_payload = "Write-Output 'AEGIS_SAFE_DEMO_V1'\nWrite-Output ('AEGIS_PID=' + $PID)\n"
    cases = [
        ('original', None, None, 'demo_match', 'demo_match', 'demo_match'),
        ('renamed', 'eventdata.path', lab_directory + '\\' + FILENAMES[1], 'not_demo', 'demo_match', 'demo_match'),
        # Same two behaviors, different wording: only a behavioral rule keeps up.
        ('reworded', 'eventdata.scriptBlockText', REWORDED, 'demo_match', 'not_demo', 'demo_match'),
        # One behavior alone is a benign look-alike and must not match.
        ('env-only', 'eventdata.scriptBlockText', 'Write-Output $env:COMPUTERNAME\n', 'demo_match', 'not_demo', 'not_demo'),
        ('pid-only', 'eventdata.scriptBlockText', old_payload, 'demo_match', 'not_demo', 'not_demo'),
        ('marker-only', 'eventdata.scriptBlockText', "Write-Output 'AEGIS_SAFE_DEMO_V1'", 'parent_dependent', 'not_demo', 'not_demo'),
        # A text rule cannot tell commented-out code from live code. Stated, not hidden.
        ('comment-only', 'eventdata.scriptBlockText', '<#\n' + PAYLOAD.decode() + '#>', 'parent_dependent', 'not_demo', 'demo_match'),
        ('unrelated', 'eventdata.scriptBlockText', "Write-Output 'unrelated synthetic control'", 'parent_dependent', 'not_demo', 'not_demo'),
        ('wrong-host', 'system.computer', 'SYNTHETIC-OTHER-' + target_host, 'not_demo', 'not_demo', 'not_demo'),
        ('wrong-provider', 'system.providerName', 'SYNTHETIC-OTHER', 'not_demo', 'not_demo', 'not_demo'),
        ('wrong-channel', 'system.channel', 'SYNTHETIC-OTHER', 'not_demo', 'not_demo', 'not_demo'),
        ('wrong-event-id', 'system.eventID', '4103', 'not_demo', 'not_demo', 'not_demo'),
        ('missing-text', 'eventdata.scriptBlockText', None, 'parent_dependent', 'not_demo', 'not_demo'),
        ('fragmented', 'eventdata.messageTotal', '2', 'not_demo', 'not_demo', 'not_demo'),
        ('missing-counter', 'eventdata.messageNumber', None, 'not_demo', 'not_demo', 'not_demo'),
    ]
    artifacts, catalog = {}, []
    for name, field, value, expected_baseline, expected_fixed, expected_behavioral in cases:
        event = copy.deepcopy(base)
        if field:
            section, key = field.split('.')
            if value is None:
                event['win'][section].pop(key)
            else:
                event['win'][section][key] = value
        if field_profile == NATIVE_PROFILE:
            # Model only our committed ASCII/LF controls at the dynamic-field
            # layer. These JSON fixtures do NOT emulate the native transport.
            data = event['win']['eventdata']
            data['path'] = data['path'].replace('\\', '\\\\')
            if 'scriptBlockText' in data:
                data['scriptBlockText'] = data['scriptBlockText'].replace('\n', ' ').rstrip(' ')
        filename = f'logtest-cases/{name}.synthetic.json'
        artifacts[filename] = (json.dumps(event, ensure_ascii=True) + '\n').encode('utf-8')
        catalog.append(dict(name=name, file=filename, expected_baseline=expected_baseline,
                            expected_fixed=expected_fixed, expected_behavioral=expected_behavioral))
    artifacts['logtest-cases/catalog.json'] = json.dumps(dict(
        synthetic_only=True, field_profile=field_profile,
        input_layer='decoded_fields_json_not_native_transport',
        note='Expected demo ID, conditional on verified parent chain. Not lab evidence.',
        cases=catalog), indent=2).encode('utf-8')
    return artifacts


def prepare_kit(*, output_dir: Path, lab_directory: str, target_host: str,
                rule_id: int, parent_sid: int, occupied_ids: frozenset[int],
                field_profile: str = LEGACY_PROFILE) -> dict:
    _field_profile(field_profile)
    _ids(rule_id, parent_sid)
    _host(target_host)
    _directory(lab_directory)
    if (not isinstance(occupied_ids, frozenset)
            or any(type(i) is not int or not 1 <= i <= 999999 for i in occupied_ids)):
        raise ValueError('invalid_occupied_ids')
    if rule_id in occupied_ids or rule_id + 1 in occupied_ids:
        raise ValueError('rule_id_occupied')
    out = _output_directory(output_dir)
    payload = _asset(ROOT / 'demos/scn-001/payload.ps1')
    if payload != PAYLOAD:
        raise ValueError('reviewed_payload_changed')
    artifacts = {name: payload for name in FILENAMES}
    artifacts['Invoke-SafeDemo.ps1'] = _asset(ROOT / 'demos/scn-001/Invoke-SafeDemo.ps1')
    for revision in REVISIONS:
        artifacts[f'{revision}.xml'] = render_rule(
            revision=revision, rule_id=rule_id, parent_sid=parent_sid,
            target_host=target_host, baseline_path=lab_directory + '\\' + FILENAMES[0],
            field_profile=field_profile).encode('utf-8')
    artifacts.update(_synthetic_cases(target_host, lab_directory, field_profile))
    manifest = dict(kind='safe_demo_kit', kit_version=KIT_VERSION, scenario_id='SCN-001',
                    scenario_version='0.1.0', target_host=target_host, lab_directory=lab_directory,
                    filenames=list(FILENAMES), rule_id=rule_id, parent_sid=parent_sid,
                    field_profile=field_profile,
                    occupied_ids_declared=sorted(occupied_ids),
                    payload_sha256=hashlib.sha256(payload).hexdigest(),
                    artifact_sha256={name: hashlib.sha256(data).hexdigest() for name, data in artifacts.items()})
    # Write manifest LAST: its absence unambiguously marks an incomplete output.
    try:
        out.mkdir(mode=0o700)
        (out / 'logtest-cases').mkdir(mode=0o700)
        for name, data in artifacts.items():
            _no_links(out / name)
            with (out / name).open('xb') as stream:
                stream.write(data)
        for name, expected in manifest['artifact_sha256'].items():
            if hashlib.sha256(_asset(out / name)).hexdigest() != expected:
                raise ValueError('artifact_changed_during_creation')
        _no_links(out / 'kit.json')
        with (out / 'kit.json').open('xb') as stream:
            stream.write((json.dumps(manifest, ensure_ascii=True, indent=2) + '\n').encode('utf-8'))
    except FileExistsError as exc:
        raise ValueError('output_exists_or_conflict') from exc
    return manifest


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'error: invalid_arguments; use --help\n')


def main(argv=None):
    parser = _Parser(description=__doc__)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--lab-directory', required=True)
    parser.add_argument('--target-host', required=True)
    parser.add_argument('--rule-id', type=int, required=True)
    parser.add_argument('--parent-sid', type=int, required=True)
    parser.add_argument('--occupied-ids', required=True,
                        help='Comma-separated rule IDs from operator inventory; use none if verified empty.')
    parser.add_argument('--field-profile', default=LEGACY_PROFILE,
                        choices=(LEGACY_PROFILE, NATIVE_PROFILE),
                        help='Explicit rule-field representation; no automatic source normalization.')
    args = parser.parse_args(argv)
    try:
        occupied = frozenset() if args.occupied_ids == 'none' else frozenset(map(int, args.occupied_ids.split(',')))
        result = prepare_kit(output_dir=Path(args.output_dir), lab_directory=args.lab_directory,
                             target_host=args.target_host, rule_id=args.rule_id,
                             parent_sid=args.parent_sid, occupied_ids=occupied,
                             field_profile=args.field_profile)
    except (ValueError, OSError, UnicodeError):
        print('error: invalid kit input or local IO; verify inputs and inspect any incomplete output.', file=sys.stderr)
        return 2
    print(json.dumps({'kind': result['kind'], 'payload_sha256': result['payload_sha256'],
                      'status': 'prepared_not_executed'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
