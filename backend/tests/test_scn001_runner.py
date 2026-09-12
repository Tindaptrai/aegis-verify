"""Exercise the real PowerShell runner's fail-closed preflight. No lab execution."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / 'demos/scn-001/Invoke-SafeDemo.ps1'


@pytest.fixture
def ps():
    exe = shutil.which('powershell.exe')
    if os.name != 'nt' or not exe:
        pytest.skip('Windows PowerShell 5.1 is unavailable')
    return exe


def test_runner_parses_without_executing(ps):
    assert RUNNER.is_file(), 'Safe runner has not been implemented'
    command = "$t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$t,[ref]$e); if ($e.Count) { exit 2 }"
    # -Command argument handling differs from -File; put only a trusted repo path in the command.
    command = command.replace('$args[0]', "'" + str(RUNNER).replace("'", "''") + "'")
    result = subprocess.run([ps, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


@pytest.fixture
def kit(tmp_path):
    spec = importlib.util.spec_from_file_location('runner_kit_builder', ROOT/'scripts/prepare_scn001_kit.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = tmp_path / 'kit'
    manifest = module.prepare_kit(output_dir=out, lab_directory=str(out),
                                  target_host=os.environ.get('COMPUTERNAME', 'SYNTHETIC'),
                                  rule_id=119901, parent_sid=91816, occupied_ids=frozenset())
    return out, manifest


def invoke(ps, kit, tmp_path, **changes):
    assert RUNNER.is_file(), 'Safe runner has not been implemented'
    out, manifest = kit
    args = dict(KitDirectory=str(out), RunDirectory=str(tmp_path/'uncreated-run'),
                RunId='synthetic-test', RunLabel='Rehearsal',
                ExpectedComputerName=manifest['target_host'], AppliedRuleRevision='baseline',
                AppliedRuleSha256=manifest['artifact_sha256']['baseline.xml']) | changes
    command = [ps, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(RUNNER)]
    for name, value in args.items():
        command.extend(['-' + name, value])
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    if 'PSSecurityException' in result.stderr or 'running scripts is disabled' in result.stderr:
        pytest.skip('PowerShell execution policy blocks script tests; no bypass used')
    assert not (tmp_path/'uncreated-run').exists()
    return result


def test_wrong_host_never_launches(ps, kit, tmp_path):
    result = invoke(ps, kit, tmp_path, ExpectedComputerName='SYNTHETIC-WRONG-TARGET')
    assert result.returncode == 2
    assert 'AEGIS_WRONG_HOST' in result.stderr
    assert 'AEGIS_PID=' not in result.stdout


def test_documented_native_hashtable_splat_preflight(ps, kit, tmp_path):
    out, manifest = kit
    args = dict(KitDirectory=str(out), RunDirectory=str(tmp_path/'uncreated-run'),
                RunId='synthetic-test', RunLabel='Rehearsal',
                ExpectedComputerName='SYNTHETIC-WRONG-TARGET', AppliedRuleRevision='baseline',
                AppliedRuleSha256=manifest['artifact_sha256']['baseline.xml'])
    entries = ';'.join(name + "='" + value.replace("'", "''") + "'" for name, value in args.items())
    exe, runner = str(ps).replace("'", "''"), str(RUNNER).replace("'", "''")
    command = f"$p=@{{{entries}}}; & '{exe}' -NoLogo -NoProfile -NonInteractive -File '{runner}' @p; exit $LASTEXITCODE"
    result = subprocess.run([ps, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command],
                            capture_output=True, text=True, timeout=15)
    if 'PSSecurityException' in result.stderr or 'running scripts is disabled' in result.stderr:
        pytest.skip('PowerShell policy blocks script tests; no bypass used')
    assert result.returncode == 2
    assert 'AEGIS_WRONG_HOST' in result.stderr
    assert not (tmp_path/'uncreated-run').exists()


@pytest.mark.parametrize('label,revision', [('A', 'fixed'), ('B', 'fixed'), ('C', 'baseline'), ('x', 'baseline')])
def test_wrong_revision_or_label_never_launches(ps, kit, tmp_path, label, revision):
    result = invoke(ps, kit, tmp_path, RunLabel=label, AppliedRuleRevision=revision)
    assert result.returncode == 2
    assert 'AEGIS_INVALID_RUN_SELECTION' in result.stderr


def test_hash_declaration_must_match_selected_rule(ps, kit, tmp_path):
    result = invoke(ps, kit, tmp_path, AppliedRuleSha256='0' * 64)
    assert result.returncode == 2
    assert 'AEGIS_RULE_HASH_MISMATCH' in result.stderr


def test_tampered_payload_even_with_rewritten_hash_is_not_executed(ps, kit, tmp_path):
    out, manifest = kit
    altered = b"Write-Output 'SYNTHETIC UNREVIEWED SCRIPT'\n"
    for name in ('lab_update.ps1', 'maintenance_check.ps1'):
        (out/name).write_bytes(altered)
        manifest['artifact_sha256'][name] = hashlib.sha256(altered).hexdigest()
    manifest['payload_sha256'] = hashlib.sha256(altered).hexdigest()
    (out/'kit.json').write_text(json.dumps(manifest), encoding='utf-8')
    result = invoke(ps, kit, tmp_path)
    assert result.returncode == 2
    assert 'AEGIS_UNREVIEWED_PAYLOAD' in result.stderr
    assert 'SYNTHETIC UNREVIEWED SCRIPT' not in result.stdout


@pytest.mark.parametrize('change', ['path', 'version', 'invalid-json', 'missing-payload'])
def test_bad_kit_refused(ps, kit, tmp_path, change):
    out, manifest = kit
    if change == 'path':
        manifest['filenames'][0] = '..\\other.ps1'
    elif change == 'version':
        manifest['kit_version'] = '999.0.0'
    elif change == 'missing-payload':
        (out/'maintenance_check.ps1').unlink()
    if change == 'invalid-json':
        (out/'kit.json').write_text('{')
    else:
        (out/'kit.json').write_text(json.dumps(manifest), encoding='utf-8')
    result = invoke(ps, kit, tmp_path)
    assert result.returncode == 2
    assert 'AEGIS_' in result.stderr


@pytest.mark.parametrize('field', ['kind', 'target_host', 'lab_directory', 'payload_sha256'])
def test_manifest_scalar_fields_cannot_be_arrays(ps, kit, tmp_path, field):
    out, manifest = kit
    real_host = manifest['target_host']
    manifest[field] = []
    (out/'kit.json').write_text(json.dumps(manifest), encoding='utf-8')
    result = invoke(ps, kit, tmp_path, ExpectedComputerName=real_host)
    assert result.returncode == 2
    assert 'AEGIS_INVALID_KIT_MANIFEST' in result.stderr


def test_repo_output_refused_before_execution(ps, kit, tmp_path):
    # This dev checkout is not an approved execution target. The output directory
    # is intentionally within the repo and must fail before telemetry/launch.
    result = invoke(ps, kit, tmp_path)
    assert result.returncode == 2
    assert 'AEGIS_RUN_OUTPUT_IN_REPOSITORY' in result.stderr


@pytest.mark.parametrize('run_id', ['', 'a b', '../run', 'x' * 65])
def test_invalid_run_id_refused(ps, kit, tmp_path, run_id):
    # An empty string cannot roundtrip as a -File CLI argument on PS5.1; use a space.
    result = invoke(ps, kit, tmp_path, RunId=run_id or ' ')
    assert result.returncode == 2
    assert 'AEGIS_INVALID_RUN_ID' in result.stderr


@pytest.mark.parametrize('path', ['relative', r'C:\a\..\b', r'\\server\share\run', r'C:\a:stream'])
def test_unsafe_run_path_refused(ps, kit, tmp_path, path):
    result = invoke(ps, kit, tmp_path, RunDirectory=path)
    assert result.returncode == 2
    assert 'AEGIS_INVALID_LOCAL_PATH' in result.stderr


def test_existing_external_output_untouched(ps, kit, tmp_path):
    with tempfile.TemporaryDirectory(prefix='aegis-runner-test-') as directory:
        keep = Path(directory) / 'keep.txt'
        keep.write_text('synthetic user data')
        # Windows TEMP may use an 8.3 alias containing '~', outside our path profile.
        result = invoke(ps, kit, tmp_path, RunDirectory=str(Path(directory).resolve()))
        assert result.returncode == 2
        assert 'AEGIS_RUN_OUTPUT_EXISTS' in result.stderr
        assert keep.read_text() == 'synthetic user data'
        assert list(Path(directory).iterdir()) == [keep]


def test_reparse_kit_refused(ps, kit, tmp_path):
    out, manifest = kit
    link = tmp_path / 'kit-link'
    try:
        link.symlink_to(out, target_is_directory=True)
    except OSError:
        pytest.skip('Symlink creation unavailable')
    result = invoke(ps, kit, tmp_path, KitDirectory=str(link))
    assert result.returncode == 2
    assert 'AEGIS_REPARSE_PATH' in result.stderr


def invoke_functions(ps, names, command):
    """Load only named function ASTs, never the runner entrypoint or Execute path."""
    path = str(RUNNER).replace("'", "''")
    selection = ','.join("'" + name + "'" for name in names)
    source = f"""
$ErrorActionPreference='Stop'
$t=$null; $e=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile('{path}',[ref]$t,[ref]$e)
$wanted=@({selection})
$functions=@($ast.FindAll({{ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -in $wanted }},$true))
if ($functions.Count -ne $wanted.Count) {{ exit 90 }}
foreach ($f in $functions) {{ . ([scriptblock]::Create($f.Extent.Text)) }}
{command}
"""
    return subprocess.run([ps, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', source],
                          capture_output=True, text=True, timeout=15)


@pytest.mark.parametrize('directory_length,accepted', [(206, True), (207, False),
                                                       (208, False), (218, False), (230, False)])
def test_run_directory_reserves_space_for_output_filenames(ps, directory_length, accepted):
    # Real existing parent, no directory/file creation by the runner or any child launch.
    with tempfile.TemporaryDirectory(prefix='aegis-path-boundary-') as directory:
        parent = Path(directory).resolve()
        out = parent / ('r' * (directory_length - len(str(parent)) - 1))
        assert len(str(out)) == directory_length
        path = str(out).replace("'", "''")
        result = invoke_functions(ps, ['Assert-AegisPath', 'Assert-AegisRunDirectory'], f"""
try {{ Assert-AegisRunDirectory '{path}'; exit 0 }}
catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 2 }}
""")
        assert result.returncode == (0 if accepted else 2), result.stderr
        if not accepted:
            assert 'AEGIS_INVALID_LOCAL_PATH' in result.stderr
        assert not out.exists()
        assert not list(parent.iterdir())


def test_preflight_refuses_output_that_would_fail_after_child_start(ps, kit, tmp_path):
    with tempfile.TemporaryDirectory(prefix='aegis-path-preflight-') as directory:
        parent = Path(directory).resolve()
        out = parent / ('r' * (208 - len(str(parent)) - 1))
        result = invoke(ps, kit, tmp_path, RunDirectory=str(out))
        assert result.returncode == 2
        assert 'AEGIS_INVALID_LOCAL_PATH' in result.stderr
        assert 'ready' not in result.stdout
        assert not out.exists()


@pytest.mark.parametrize('case', ['ok', 'nonzero', 'timeout', 'wrong-pid', 'extra-output', 'stderr'])
def test_child_result_validation_without_launching(ps, case):
    code = 1 if case == 'nonzero' else 0
    timed_out = '$true' if case == 'timeout' else '$false'
    child_pid = 4243 if case == 'wrong-pid' else 4242
    extra = '`nextra' if case == 'extra-output' else ''
    error = 'synthetic-error' if case == 'stderr' else ''
    result = invoke_functions(ps, ['Assert-AegisChildResult'], f"""
try {{
  Assert-AegisChildResult {code} {timed_out} 4242 "AEGIS_SAFE_DEMO_V1`r`nAEGIS_PID={child_pid}`r`n{extra}" '{error}'
  exit 0
}} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 2 }}
""")
    assert result.returncode == (0 if case == 'ok' else 2), result.stderr
    if case != 'ok':
        assert 'AEGIS_EXECUTION_FAILED' in result.stderr


@pytest.mark.parametrize('case', ['missing-service', 'missing-channel', 'denied-log', 'ready'])
def test_telemetry_guards_with_explicit_test_doubles(ps, case):
    # These are controlled unit doubles, not a claim about the development host's telemetry.
    service = "return $null" if case == 'missing-service' else "return [pscustomobject]@{Status='Running'}"
    if case == 'missing-channel':
        log = "return [pscustomobject]@{IsEnabled=$false}"
    elif case == 'denied-log':
        log = "throw 'synthetic access denied'"
    else:
        log = "return [pscustomobject]@{IsEnabled=$true; Id=4104}"
    result = invoke_functions(ps, ['Assert-AegisTelemetry'], f"""
function Get-Service {{ param($Name, $ErrorAction) {service} }}
function Get-WinEvent {{ param($ListLog, $FilterHashtable, $MaxEvents) {log} }}
try {{ Assert-AegisTelemetry; exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 2 }}
""")
    assert result.returncode == (0 if case == 'ready' else 2), result.stderr
    if case != 'ready':
        assert 'AEGIS_TELEMETRY_' in result.stderr
