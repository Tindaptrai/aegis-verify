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
PAYLOAD = b"Write-Output 'AEGIS_SAFE_DEMO_V1'\nWrite-Output ('AEGIS_PID=' + $PID)\n"
FILENAMES = ('lab_update.ps1', 'maintenance_check.ps1')


def _ids(rule_id, parent_sid):
    if type(rule_id) is not int or not 100000 <= rule_id <= 120000:
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
                target_host: str, baseline_path: str) -> str:
    _ids(rule_id, parent_sid)
    _host(target_host)
    if revision not in ('baseline', 'fixed'):
        raise ValueError('invalid_revision')
    if not isinstance(baseline_path, str) or not baseline_path.endswith('\\lab_update.ps1'):
        raise ValueError('invalid_baseline_path')
    _directory(baseline_path[:-len('\\lab_update.ps1')])
    lines = PAYLOAD.decode('ascii').splitlines()
    script_pattern = r'\A' + r'\r?\n'.join(map(re.escape, lines)) + r'(?:\r?\n)?\z'
    template = _asset(ROOT / 'detections/wazuh/scn-001' / f'{revision}.xml.template')
    return Template(template.decode('utf-8')).substitute(
        rule_id=str(rule_id), parent_sid=str(parent_sid),
        host_pattern=escape(_path_pattern(target_host)),
        path_pattern=escape(_path_pattern(baseline_path)),
        script_pattern=escape(script_pattern))


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


def _synthetic_cases(target_host, lab_directory):
    """Parameterize a committed test fixture; never read or generate lab evidence."""
    base = json.loads(_asset(ROOT / 'tests/fixtures/demo/scn-001/rule-cases/base.synthetic.json'))
    base['win']['system']['computer'] = target_host
    base['win']['eventdata']['path'] = lab_directory + '\\' + FILENAMES[0]
    cases = [
        ('original', None, None, 'demo_match', 'demo_match'),
        ('renamed', 'eventdata.path', lab_directory + '\\' + FILENAMES[1], 'not_demo', 'demo_match'),
        ('marker-only', 'eventdata.scriptBlockText', "Write-Output 'AEGIS_SAFE_DEMO_V1'", 'parent_dependent', 'not_demo'),
        ('comment-only', 'eventdata.scriptBlockText', '<#\n' + PAYLOAD.decode() + '#>', 'parent_dependent', 'not_demo'),
        ('unrelated', 'eventdata.scriptBlockText', "Write-Output 'unrelated synthetic control'", 'parent_dependent', 'not_demo'),
        ('wrong-host', 'system.computer', 'SYNTHETIC-OTHER-' + target_host, 'not_demo', 'not_demo'),
        ('wrong-provider', 'system.providerName', 'SYNTHETIC-OTHER', 'not_demo', 'not_demo'),
        ('wrong-channel', 'system.channel', 'SYNTHETIC-OTHER', 'not_demo', 'not_demo'),
        ('wrong-event-id', 'system.eventID', '4103', 'not_demo', 'not_demo'),
        ('missing-text', 'eventdata.scriptBlockText', None, 'parent_dependent', 'not_demo'),
        ('fragmented', 'eventdata.messageTotal', '2', 'not_demo', 'not_demo'),
        ('missing-counter', 'eventdata.messageNumber', None, 'not_demo', 'not_demo'),
    ]
    artifacts, catalog = {}, []
    for name, field, value, expected_baseline, expected_fixed in cases:
        event = copy.deepcopy(base)
        if field:
            section, key = field.split('.')
            if value is None:
                event['win'][section].pop(key)
            else:
                event['win'][section][key] = value
        filename = f'logtest-cases/{name}.synthetic.json'
        artifacts[filename] = (json.dumps(event, ensure_ascii=True) + '\n').encode('utf-8')
        catalog.append(dict(name=name, file=filename, expected_baseline=expected_baseline,
                            expected_fixed=expected_fixed))
    artifacts['logtest-cases/catalog.json'] = json.dumps(dict(
        synthetic_only=True, note='Expected demo ID, conditional on verified parent chain. Not lab evidence.',
        cases=catalog), indent=2).encode('utf-8')
    return artifacts


def prepare_kit(*, output_dir: Path, lab_directory: str, target_host: str,
                rule_id: int, parent_sid: int, occupied_ids: frozenset[int]) -> dict:
    _ids(rule_id, parent_sid)
    _host(target_host)
    _directory(lab_directory)
    if (not isinstance(occupied_ids, frozenset)
            or any(type(i) is not int or not 1 <= i <= 999999 for i in occupied_ids)):
        raise ValueError('invalid_occupied_ids')
    if rule_id in occupied_ids:
        raise ValueError('rule_id_occupied')
    out = _output_directory(output_dir)
    payload = _asset(ROOT / 'demos/scn-001/payload.ps1')
    if payload != PAYLOAD:
        raise ValueError('reviewed_payload_changed')
    artifacts = {name: payload for name in FILENAMES}
    artifacts['Invoke-SafeDemo.ps1'] = _asset(ROOT / 'demos/scn-001/Invoke-SafeDemo.ps1')
    for revision in ('baseline', 'fixed'):
        artifacts[f'{revision}.xml'] = render_rule(
            revision=revision, rule_id=rule_id, parent_sid=parent_sid,
            target_host=target_host, baseline_path=lab_directory + '\\' + FILENAMES[0]).encode('utf-8')
    artifacts.update(_synthetic_cases(target_host, lab_directory))
    manifest = dict(kind='safe_demo_kit', kit_version='0.1.0', scenario_id='SCN-001',
                    scenario_version='0.1.0', target_host=target_host, lab_directory=lab_directory,
                    filenames=list(FILENAMES), rule_id=rule_id, parent_sid=parent_sid,
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
    args = parser.parse_args(argv)
    try:
        occupied = frozenset() if args.occupied_ids == 'none' else frozenset(map(int, args.occupied_ids.split(',')))
        result = prepare_kit(output_dir=Path(args.output_dir), lab_directory=args.lab_directory,
                             target_host=args.target_host, rule_id=args.rule_id,
                             parent_sid=args.parent_sid, occupied_ids=occupied)
    except (ValueError, OSError, UnicodeError):
        print('error: invalid kit input or local IO; verify inputs and inspect any incomplete output.', file=sys.stderr)
        return 2
    print(json.dumps({'kind': result['kind'], 'payload_sha256': result['payload_sha256'],
                      'status': 'prepared_not_executed'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
