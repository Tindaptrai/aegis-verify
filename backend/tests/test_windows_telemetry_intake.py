"""Synthetic offline CLI and ledger checks; no live or raw lab dependency."""

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

import pytest

from aegis_verify.intake import IntakeError
from aegis_verify.intake.contracts import parse_manifest
from aegis_verify.intake.loader import load_bundle
from aegis_verify.scenario_loader import parse_scenario_yaml
from aegis_verify.validation import scenario_fingerprint
from test_windows_telemetry import CONTEXT, PROFILES, change, parse, sample


ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / 'scenarios/SCN-001-powershell-execution.yaml'


def encode(data):
    return json.dumps(data, ensure_ascii=True, indent=2).encode()


def entry(kind, key, raw, name=None):
    return dict(path=name or f'{kind}.json', source_ref=name or kind, parser=key,
                sha256=sha256(raw).hexdigest(),
                context={k: CONTEXT[k] for k in ('ingested_at', 'collection_mode')})


def manifest(files):
    return dict(bundle_schema_version='0.1.0', environment_id='synthetic-env', files=files)


@pytest.mark.parametrize('kind,api,key', PROFILES)
def test_registry_dispatch_and_line_level_ledger(tmp_path, kind, api, key):
    raw = sample(kind)
    (tmp_path / f'{kind}.json').write_bytes(raw)
    result = load_bundle(tmp_path, parse_manifest(manifest([entry(kind, key, raw)])))
    assert result.events == (parse(kind, raw, source_ref=kind).event,)
    ledger = result.ledger[0]
    assert ledger.parser == key and ledger.status == 'parsed'
    assert ledger.raw_event_ref == kind + '#record=1'
    assert ledger.event_id == result.events[0].event_id
    assert ledger.raw_event_hash == sha256(raw).hexdigest()
    assert ledger.line_start == 1 and ledger.line_end == len(raw.splitlines())
    assert (tmp_path / f'{kind}.json').read_bytes() == raw


@pytest.mark.parametrize('kind,api,key', PROFILES)
def test_new_registry_keys_still_verify_hash(tmp_path, kind, api, key):
    raw = sample(kind)
    (tmp_path / f'{kind}.json').write_bytes(raw + b'\n')
    with pytest.raises(IntakeError):
        load_bundle(tmp_path, parse_manifest(manifest([entry(kind, key, raw)])))


def write_bundle(folder, *, detection=False, fragmented=False):
    folder.mkdir(exist_ok=True)
    files = []
    for kind, _, key in PROFILES:
        raw = sample(kind)
        if fragmented and kind == 'powershell4104':
            raw = change(raw, '_source.data.win.eventdata.messageTotal', '2')
        (folder / f'{kind}.json').write_bytes(raw)
        files.append(entry(kind, key, raw))
    if detection:
        raw = change(sample('powershell4104'), '_source.rule.id', 'synthetic-detection-only')
        raw = change(raw, '_source.id', 'synthetic-detection-record')
        (folder / 'detection.json').write_bytes(raw)
        files.append(entry('powershell4104', 'wazuh-powershell4104-v1', raw, 'detection.json'))
    rules = []
    for suffix, provider, match in [
        ('01', 'Microsoft-Windows-Sysmon', [{'field': 'process_name', 'op': 'eq', 'value': r'C:\Synthetic\powershell.exe'}]),
        ('02', 'Microsoft-Windows-PowerShell', [{'field': 'file_path', 'op': 'eq', 'value': r'C:\Synthetic\example.ps1'}]),
    ]:
        rules.append(dict(assertion_id='SCN-001-A' + suffix, role='telemetry', capability='supported',
                          source_type='wazuh', scope=[
                              {'field': 'hostname', 'op': 'eq', 'binding': 'target'},
                              {'field': 'event_provider', 'op': 'eq', 'value': provider},
                          ], match=match))
    rules.append(dict(assertion_id='SCN-001-A03', role='detection', capability='supported',
                      source_type='wazuh', scope=[{'field': 'hostname', 'op': 'eq', 'binding': 'target'}],
                      match=[{'field': 'rule_id', 'op': 'eq', 'value': 'synthetic-detection-only'}],
                      correlation=dict(anchor_assertion_id='SCN-001-A01', join_pairs=[
                          {'target_field': 'hostname', 'anchor_field': 'hostname'},
                          {'target_field': 'process_id', 'anchor_field': 'process_id'},
                      ], min_delta_ns=0, max_delta_ns=5_000_000_000)))
    profile = dict(profile_schema_version='0.1.0', profile_id='synthetic-windows-telemetry',
                   profile_version='0.1.0', scenario_id='SCN-001', scenario_version='0.1.0',
                   scenario_fingerprint=scenario_fingerprint(parse_scenario_yaml(
                       SCENARIO.read_text(encoding='utf-8'), source_name='synthetic-test-scenario')),
                   rules=rules)
    context = dict(run_id='synthetic-windows-telemetry', environment_id='synthetic-env',
                   start='2026-01-01T00:00:00Z', end='2026-01-01T00:01:00Z',
                   bindings=[{'name': 'target', 'value': 'synthetic-endpoint'}], declarations=[])
    for name, data in [('inputs.json', manifest(files)), ('profile.json', profile), ('context.json', context)]:
        (folder / name).write_bytes(encode(data))


def cli(folder):
    return subprocess.run([sys.executable, '-m', 'aegis_verify', 'validate', '--scenario', str(SCENARIO),
                           '--fixture', str(folder), '--format=json'], capture_output=True, text=True, check=False)


@pytest.mark.parametrize('detection,status,exit_code', [(False, 'Inconclusive', 3), (True, 'Detected', 0)])
def test_cli_telemetry_alone_is_not_proof_of_detection(tmp_path, detection, status, exit_code):
    original = SCENARIO.read_bytes()
    write_bundle(tmp_path, detection=detection)
    result = cli(tmp_path)
    assert result.returncode == exit_code, result.stderr
    assert result.stderr == ''
    report = json.loads(result.stdout)
    assert report['evaluation']['final_status'] == status
    assert 'synthetic marker' not in result.stdout
    assert SCENARIO.read_bytes() == original


def test_fragmented_record_aborts_cli_instead_of_emitting_partial_result(tmp_path):
    write_bundle(tmp_path, fragmented=True)
    result = cli(tmp_path)
    assert result.returncode == 2 and result.stdout == ''
    error = json.loads(result.stderr)['error']
    assert error['code'] == 'parser_error' and error['stage'] == 'evidence'
    assert 'synthetic marker' not in result.stderr


def test_documented_synthetic_bundle_is_inconclusive_not_lab_success():
    result = cli(ROOT / 'tests/fixtures/wazuh/windows-telemetry')
    assert result.returncode == 3, result.stderr
    report = json.loads(result.stdout)
    assert report['evaluation']['final_status'] == 'Inconclusive'
    assert len(report['evaluation']['assertions']) == 3
