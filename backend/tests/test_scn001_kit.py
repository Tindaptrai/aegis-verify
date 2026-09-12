"""Offline synthetic kit tests; these do not execute a lab payload or Wazuh."""

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/prepare_scn001_kit.py'
PAYLOAD = b"Write-Output 'AEGIS_SAFE_DEMO_V1'\nWrite-Output ('AEGIS_PID=' + $PID)\n"


@pytest.fixture
def kit_module():
    assert SCRIPT.is_file(), 'Offline kit generator has not been implemented'
    spec = importlib.util.spec_from_file_location('scn001_kit_under_test', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def options(tmp_path, **changes):
    return dict(output_dir=tmp_path / 'kit', lab_directory=r'C:\AEGIS Synthetic',
                target_host='SYNTHETIC-ENDPOINT', rule_id=119901,
                parent_sid=91816, occupied_ids=frozenset()) | changes


def test_two_names_share_reviewed_bytes(kit_module, tmp_path):
    result = kit_module.prepare_kit(**options(tmp_path))
    out = tmp_path / 'kit'
    assert (out / 'lab_update.ps1').read_bytes() == PAYLOAD
    assert (out / 'maintenance_check.ps1').read_bytes() == PAYLOAD
    assert result['payload_sha256'] == hashlib.sha256(PAYLOAD).hexdigest()
    assert result['kind'] == 'safe_demo_kit'
    assert json.loads((out / 'kit.json').read_bytes()) == result
    assert not (out / 'kit.json').read_bytes().startswith(b'\xef\xbb\xbf')
    for name, digest in result['artifact_sha256'].items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest
    assert 'collection' not in result and 'final_status' not in result
    assert (out / 'Invoke-SafeDemo.ps1').read_bytes() == (ROOT / 'demos/scn-001/Invoke-SafeDemo.ps1').read_bytes()


@pytest.mark.parametrize('revision', ['baseline', 'fixed'])
def test_rule_fields_are_scoped_and_literal(kit_module, revision):
    xml = kit_module.render_rule(revision=revision, rule_id=119901,
                                parent_sid=91816, target_host='SYNTHETIC.ENDPOINT',
                                baseline_path=r'C:\AEGIS Synthetic\lab_update.ps1')
    rule = ET.fromstring(xml).find('rule')
    assert rule.attrib == {'id': '119901', 'level': '5'}
    assert rule.findtext('if_sid') == '91816'
    fields = {el.attrib['name']: el.text for el in rule.findall('field')}
    assert fields['win.system.computer'] == r'\ASYNTHETIC\.ENDPOINT\z'
    assert fields['win.system.eventID'] == r'\A4104\z'
    assert fields['win.eventdata.messageNumber'] == r'\A1\z'
    assert fields['win.eventdata.messageTotal'] == r'\A1\z'
    assert not any(name.startswith('data.') for name in fields)
    assert all(el.attrib['type'] == 'pcre2' for el in rule.findall('field'))
    if revision == 'baseline':
        assert 'win.eventdata.path' in fields
        assert 'win.eventdata.scriptBlockText' not in fields
    else:
        assert 'win.eventdata.path' not in fields
        pattern = fields['win.eventdata.scriptBlockText']
        # Characterization of the generated literal/newline subset, NOT a PCRE2 test.
        portable = pattern.replace(r'\z', r'\Z')
        for text in (PAYLOAD.decode(), PAYLOAD.decode().replace('\n', '\r\n'),
                     PAYLOAD.decode().rstrip('\n')):
            assert re.search(portable, text)
        for text in ('AEGIS_SAFE_DEMO_V1', '# ' + PAYLOAD.decode(),
                     '<#' + PAYLOAD.decode() + '#>', PAYLOAD.decode() + 'Get-Date',
                     PAYLOAD.decode() + '\n', PAYLOAD.decode() + '\x00'):
            assert not re.search(portable, text)


@pytest.mark.parametrize('change', [
    {'rule_id': True}, {'rule_id': '119901'}, {'rule_id': 99999}, {'rule_id': 120001},
    {'parent_sid': False}, {'parent_sid': '91816'}, {'parent_sid': 0},
    {'parent_sid': 1000000}, {'parent_sid': 119901},
    {'occupied_ids': frozenset({119901})}, {'occupied_ids': frozenset({True})},
    {'target_host': ''}, {'target_host': ' A'}, {'target_host': 'A\nB'},
    {'target_host': 'A' * 256}, {'target_host': 'x</field>'},
    {'lab_directory': 'relative'}, {'lab_directory': 'C:relative'},
    {'lab_directory': '\\\\server\\share'}, {'lab_directory': 'C:\\'},
    {'lab_directory': 'C:\\A\\..\\B'}, {'lab_directory': 'C:\\A\\.\\B'},
    {'lab_directory': 'C:\\A:stream'}, {'lab_directory': 'C:\\a"b'},
    {'lab_directory': 'C:\\A\\'}, {'lab_directory': 'C:\\A. '},
    {'lab_directory': 'C:\\A\\NUL'}, {'lab_directory': 'C:\\A\\con.txt'},
    {'lab_directory': 'C:\\a*b'}, {'lab_directory': 'C:\\' + 'a' * 200},
    {'lab_directory': 'C:/A'}, {'lab_directory': 'C:\\A\nB'},
])
def test_bad_config_rejected_before_writing(kit_module, tmp_path, change):
    with pytest.raises(ValueError):
        kit_module.prepare_kit(**options(tmp_path, **change))
    assert not (tmp_path / 'kit').exists()


def test_existing_output_untouched(kit_module, tmp_path):
    out = tmp_path / 'kit'
    out.mkdir()
    (out / 'keep.txt').write_text('user data')
    with pytest.raises(ValueError):
        kit_module.prepare_kit(**options(tmp_path))
    assert list(out.iterdir()) == [out / 'keep.txt']
    assert (out / 'keep.txt').read_text() == 'user data'


@pytest.mark.parametrize('relative', [True, False])
def test_output_path_must_be_unambiguous(kit_module, tmp_path, relative):
    out = Path('relative-kit') if relative else tmp_path / 'absent-parent' / 'kit'
    with pytest.raises(ValueError):
        kit_module.prepare_kit(**options(tmp_path, output_dir=out))
    assert not (tmp_path / 'absent-parent').exists()


def test_unknown_revision_rejected(kit_module):
    with pytest.raises(ValueError):
        kit_module.render_rule(revision='typo', rule_id=119901, parent_sid=91816,
                               target_host='SYNTHETIC', baseline_path=r'C:\A\lab_update.ps1')


def test_symlink_output_parent_refused(kit_module, tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    link = tmp_path / 'linked'
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f'Symlink creation unavailable: {exc.winerror if hasattr(exc, "winerror") else exc.errno}')
    with pytest.raises(ValueError, match='symlink_or_reparse'):
        kit_module.prepare_kit(**options(tmp_path, output_dir=link / 'kit'))
    assert not list(target.iterdir())


def test_kit_contains_explicit_synthetic_cases(kit_module, tmp_path):
    result = kit_module.prepare_kit(**options(tmp_path))
    out = tmp_path / 'kit'
    catalog = json.loads((out / 'logtest-cases/catalog.json').read_bytes())
    assert catalog['synthetic_only'] is True
    cases = {item['name']: item for item in catalog['cases']}
    original = json.loads((out / cases['original']['file']).read_bytes())
    renamed = json.loads((out / cases['renamed']['file']).read_bytes())
    assert original['win']['eventdata']['scriptBlockText'].encode() == PAYLOAD
    assert renamed['win']['eventdata']['path'] == r'C:\AEGIS Synthetic\maintenance_check.ps1'
    assert original['win']['system']['computer'] == 'SYNTHETIC-ENDPOINT'
    assert original['aegis_synthetic_test_only'] is True
    assert cases['renamed']['expected_fixed'] == 'demo_match'
    assert cases['renamed']['expected_baseline'] == 'not_demo'
    for name in ('marker-only', 'comment-only', 'wrong-host', 'wrong-event-id',
                 'missing-text', 'fragmented', 'missing-counter'):
        assert cases[name]['expected_fixed'] == 'not_demo'
    assert 'logtest-cases/catalog.json' in result['artifact_sha256']


def test_cli_does_not_echo_invalid_sensitive_input(kit_module, tmp_path):
    result = subprocess.run([sys.executable, str(SCRIPT), '--output-dir', str(tmp_path/'kit'),
                             '--lab-directory', 'synthetic-secret-invalid-path',
                             '--target-host', 'SYNTHETIC', '--rule-id', '119901',
                             '--parent-sid', '91816', '--occupied-ids', '100001'],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 2
    assert 'synthetic-secret-invalid-path' not in result.stdout + result.stderr
    assert not (tmp_path / 'kit').exists()


def test_readback_mismatch_never_publishes_manifest(kit_module, tmp_path, monkeypatch):
    original = kit_module._asset
    out = tmp_path / 'kit'

    def changed(path):
        if path == out / 'lab_update.ps1':
            return b'synthetic concurrent modification'
        return original(path)

    monkeypatch.setattr(kit_module, '_asset', changed)
    with pytest.raises(ValueError, match='artifact_changed'):
        kit_module.prepare_kit(**options(tmp_path))
    assert not (out / 'kit.json').exists()


@pytest.mark.parametrize('area', ['demos', 'tests/fixtures/raw-evidence', '.git'])
def test_protected_repo_output_refused(kit_module, tmp_path, area):
    out = ROOT / area / 'uncreated-synthetic-kit'
    with pytest.raises(ValueError):
        kit_module.prepare_kit(**options(tmp_path, output_dir=out))
    assert not out.exists()


def test_output_in_another_checkout_refused(kit_module, tmp_path):
    checkout = tmp_path / 'another-checkout'
    checkout.mkdir()
    (checkout / '.git').write_text('synthetic git marker')
    with pytest.raises(ValueError, match='use_external_output_or_build'):
        kit_module.prepare_kit(**options(tmp_path, output_dir=checkout / 'kit'))
    assert not (checkout / 'kit').exists()
