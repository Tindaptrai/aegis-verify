"""Run the real PowerShell launcher against isolated files and loopback sockets."""

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[2]
SHELLS = [p for name in ('powershell', 'pwsh') if (p := shutil.which(name))]
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows launcher')


@pytest.fixture(params=SHELLS or [None])
def shell(request):
    if request.param is None:
        pytest.skip('PowerShell unavailable')
    return request.param


@pytest.fixture
def layout(tmp_path):
    source = ROOT / 'Start-Aegis.ps1'
    assert source.is_file(), 'Start-Aegis.ps1 has not been implemented'
    repo = tmp_path / 'checkout with spaces'
    repo.mkdir()
    script = repo / source.name
    shutil.copyfile(source, script)
    static = repo / 'frontend' / 'dist'
    static.mkdir(parents=True)
    (static / 'index.html').write_text('<!doctype html><title>launcher smoke</title>')
    reports = tmp_path / 'reports private'
    reports.mkdir()
    fixture = ROOT / 'tests/fixtures/dashboard/after-detected.json'
    shutil.copyfile(fixture, reports / 'sample.json')
    return script, reports, static


def command(shell, layout, *extra):
    script, reports, _ = layout
    return [shell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script),
            '-Reports', str(reports), '-PythonPath', sys.executable, *extra]


def run(shell, layout, *extra):
    return subprocess.run(command(shell, layout, *extra), cwd=layout[1].parent,
                          capture_output=True, text=True, timeout=20)


def test_missing_reports_are_rejected_without_creation(shell, layout):
    shutil.rmtree(layout[1])
    result = run(shell, layout)
    assert result.returncode != 0
    assert 'reports_missing' in result.stdout
    assert not layout[1].exists()


@pytest.mark.parametrize('value', [r'\\example.invalid\share', '//example.invalid/share',
                                  'https://example.invalid/report', 'FileSystem::C:/reports'])
@pytest.mark.parametrize('parameter', ['Reports', 'PythonPath', 'OperationsConfig'])
def test_nonlocal_paths_rejected_before_filesystem_probe(shell, layout, value, parameter):
    # Shadow the filesystem boundary so a regression cannot contact a real share.
    script = str(layout[0]).replace("'", "''")
    reports = str(layout[1]).replace("'", "''")
    python = sys.executable.replace("'", "''")
    if parameter == 'Reports':
        reports = value
    elif parameter == 'PythonPath':
        python = value
    extra = f" -OperationsConfig '{value}'" if parameter == 'OperationsConfig' else ''
    expression = ("function Test-Path { throw 'UNEXPECTED_FILESYSTEM_PROBE' }; "
                  f"& '{script}' -Reports '{reports}' -PythonPath '{python}'{extra}")
    result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', expression],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert 'local_path_required' in result.stdout
    assert 'UNEXPECTED_FILESYSTEM_PROBE' not in result.stdout + result.stderr


def test_forbidden_components_are_not_normalized_away(shell, layout):
    script = str(layout[0]).replace("'", "''")
    path = str(layout[1] / 'not-existing [x]' / '..').replace("'", "''")
    python = sys.executable.replace("'", "''")
    expression = ("function Test-Path { throw 'UNEXPECTED_FILESYSTEM_PROBE' }; "
                  f"& '{script}' -Reports '{path}' -PythonPath '{python}'")
    result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-Command', expression],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert 'invalid_path' in result.stdout
    assert 'UNEXPECTED_FILESYSTEM_PROBE' not in result.stdout + result.stderr


def test_missing_python_has_actionable_error(shell, layout):
    cmd = command(shell, layout)
    cmd[-1] = str(layout[1] / 'missing-python.exe')
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert 'python_missing' in result.stdout


def test_missing_operations_config_is_not_created(shell, layout):
    path = layout[1].parent / 'missing config.json'
    result = run(shell, layout, '-OperationsConfig', str(path))
    assert result.returncode != 0
    assert 'operations_config_missing' in result.stdout
    assert not path.exists()


def test_operations_config_forwarded_as_one_argument(shell, layout):
    path = layout[1].parent / 'operations config.json'
    path.write_text('{}')
    fake = layout[1].parent / 'python boundary.ps1'
    fake.write_text("if ($args -contains '-u') { ConvertTo-Json -InputObject @($args) -Compress }; $global:LASTEXITCODE = 0")
    cmd = command(shell, layout)
    cmd[-1] = str(fake)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    result = subprocess.run(cmd + ['-Port', str(port), '-OperationsConfig', str(path)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    args = json.loads(result.stdout.splitlines()[-1])
    assert args[args.index('--operations-config') + 1] == str(path)
    assert args[args.index('--reports') + 1] == str(layout[1])


def test_missing_default_venv_does_not_fall_back_to_path(shell, layout):
    result = subprocess.run(command(shell, layout)[:-2], capture_output=True,
                            text=True, timeout=20)
    assert result.returncode != 0
    assert 'python_missing' in result.stdout


def test_python_without_project_is_rejected(shell, layout):
    isolated = layout[1].parent / 'empty-venv'
    subprocess.run([sys.executable, '-m', 'venv', '--without-pip', str(isolated)],
                   check=True, capture_output=True, timeout=30)
    cmd = command(shell, layout)
    cmd[-1] = str(isolated / 'Scripts/python.exe')
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert 'python_environment_invalid' in result.stdout or 'package_missing' in result.stdout
    assert 'Traceback' not in result.stdout + result.stderr


def test_missing_build_is_not_installed_automatically(shell, layout):
    (layout[2] / 'index.html').unlink()
    result = run(shell, layout)
    assert result.returncode != 0
    assert 'build_missing' in result.stdout
    assert not (layout[2] / 'index.html').exists()


def test_busy_port_is_preserved(shell, layout):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        port = listener.getsockname()[1]
        result = run(shell, layout, '-Port', str(port))
        assert result.returncode != 0
        assert 'port_unavailable' in result.stdout
        with socket.create_connection(('127.0.0.1', port), timeout=2):
            pass


@pytest.mark.parametrize('port', ['0', '-1', '65536'])
def test_invalid_port_exits(shell, layout, port):
    assert run(shell, layout, '-Port', port).returncode != 0


def test_backend_path_safety_rejection_is_preserved(shell, layout):
    renamed = layout[1].with_name('reports [ambiguous]')
    layout[1].rename(renamed)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    result = run(shell, (layout[0], renamed, layout[2]), '-Port', str(port))
    assert result.returncode != 0
    assert 'invalid_path' in result.stderr + result.stdout
    assert (renamed / 'sample.json').is_file()


def test_launches_real_read_only_server_from_other_directory(shell, layout):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    before = (layout[1] / 'sample.json').read_bytes()
    process = subprocess.Popen(command(shell, layout, '-Port', str(port)),
                               cwd=layout[1].parent, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    base = f'http://127.0.0.1:{port}'
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                with opener.open(base + '/api/reports', timeout=1) as response:
                    index = json.load(response)
                break
            except OSError:
                if process.poll() is not None:
                    out, err = process.communicate(timeout=2)
                    pytest.fail(f'Launcher exited {process.returncode}: {out}\n{err}')
                if time.monotonic() >= deadline:
                    pytest.fail('Launcher startup timed out')
                time.sleep(.1)
        assert index['reports'][0]['name'] == 'sample.json'
        with opener.open(base, timeout=2) as response:
            assert b'launcher smoke' in response.read()
        with opener.open(base + '/api/reports/sample.json', timeout=2) as response:
            assert json.load(response) == json.loads(before)
        assert (layout[1] / 'sample.json').read_bytes() == before
    finally:
        # Only the process tree created by this test; never an existing server.
        if process.poll() is None:
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                           capture_output=True, timeout=10)
        process.communicate(timeout=10)
