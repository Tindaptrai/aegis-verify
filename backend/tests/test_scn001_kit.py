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
PAYLOAD = b"$facts = @{ Host = $env:COMPUTERNAME; User = $env:USERNAME; Pid = $PID }\nWrite-Output 'AEGIS_SAFE_DEMO_V1'\nWrite-Output ('AEGIS_PID=' + $facts.Pid)\n"
OLD_PAYLOAD = b"Write-Output 'AEGIS_SAFE_DEMO_V1'\nWrite-Output ('AEGIS_PID=' + $PID)\n"  # pid-only: the pre-behavioral payload, now a control
REWORDED = ("$m = [Environment]::MachineName; $u = [Environment]::UserName\n"
            "\"AEGIS_SAFE_DEMO_V1\"\n"
            "\"AEGIS_PID=\" + [System.Diagnostics.Process]::GetCurrentProcess().Id\n")
ENV_ONLY = "Write-Output $env:COMPUTERNAME\n"
REVISIONS = ('baseline', 'fixed', 'behavioral')


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


@pytest.mark.parametrize('revision', REVISIONS)
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
    elif revision == 'behavioral':
        assert 'win.eventdata.path' not in fields
        pattern = fields['win.eventdata.scriptBlockText']
        # The behavioral revision must not be built from the payload text at all:
        # no marker, no cmdlet spelling, no filename. Only the two observed
        # behaviors, in any wording, in one script block.
        for forbidden in ('AEGIS', 'Write-Output', 'lab_update', 'maintenance_check', '$facts'):
            assert forbidden not in pattern
        for text in (PAYLOAD.decode(), PAYLOAD.decode().replace('\n', ' '), REWORDED,
                     REWORDED.replace('\n', ' '), PAYLOAD.decode().lower()):
            assert re.search(pattern, text), text
        for text in (OLD_PAYLOAD.decode(), ENV_ONLY, "Write-Output 'AEGIS_SAFE_DEMO_V1'",
                     "Write-Output 'unrelated synthetic control'", '', '$x = $PID',
                     'Get-Process -Id $PID', '[Environment]::MachineName'):
            assert not re.search(pattern, text), text
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
    assert cases['renamed']['expected_behavioral'] == 'demo_match'
    # Same behavior, different wording: only the behavioral revision keeps up.
    assert cases['reworded']['expected_behavioral'] == 'demo_match'
    assert cases['reworded']['expected_fixed'] == 'not_demo'
    # Benign look-alikes: one behavior alone is not the pair.
    for name in ('env-only', 'pid-only', 'marker-only', 'unrelated'):
        assert cases[name]['expected_behavioral'] == 'not_demo', name
    # Known limit of any text rule, stated rather than hidden: commented-out code
    # still carries both behaviors as text.
    assert cases['comment-only']['expected_behavioral'] == 'demo_match'
    for name in ('missing-text', 'fragmented', 'missing-counter', 'wrong-host', 'wrong-event-id'):
        assert cases[name]['expected_behavioral'] == 'not_demo', name
    reworded = json.loads((out / cases['reworded']['file']).read_bytes())
    assert reworded['win']['eventdata']['scriptBlockText'] == REWORDED
    assert json.loads((out / cases['pid-only']['file']).read_bytes())['win']['eventdata']['scriptBlockText'].encode() == OLD_PAYLOAD
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


NATIVE_PROFILE = 'wazuh-eventchannel-4.14.4-lf-v1'
FLAT_SCRIPT = ("$facts = @{ Host = $env:COMPUTERNAME; User = $env:USERNAME; Pid = $PID } "
               "Write-Output 'AEGIS_SAFE_DEMO_V1' Write-Output ('AEGIS_PID=' + $facts.Pid)")


def native_rule(kit_module, revision):
    return ET.fromstring(kit_module.render_rule(
        revision=revision, rule_id=119901, parent_sid=91816,
        target_host='SYNTHETIC.ENDPOINT',
        baseline_path=r'C:\AEGIS Synthetic\lab_update.ps1',
        field_profile=NATIVE_PROFILE)).find('rule')


def literal_match(pattern, value):
    # Only the generated anchored literal subset; NOT the Wazuh/PCRE2 engine.
    return isinstance(value, str) and re.search(pattern.replace(r'\z', r'\Z'), value) is not None


def test_native_profile_baseline_matches_only_doubled_field_path(kit_module):
    rule = native_rule(kit_module, 'baseline')
    pattern = rule.find("field[@name='win.eventdata.path']").text
    assert literal_match(pattern, r'C:\\AEGIS Synthetic\\lab_update.ps1')
    for path in (r'C:\AEGIS Synthetic\lab_update.ps1',
                 r'C:\\AEGIS Synthetic\lab_update.ps1',
                 r'C:\\AEGIS Synthetic\\maintenance_check.ps1',
                 r'C:\\AEGIS Synthetic\\lab_updateXps1',
                 r'C:\\AEGIS Synthetic\\lab_update.ps1' + '\n'):
        assert not literal_match(pattern, path)


def test_native_profile_fixed_matches_exact_lossy_representation_only(kit_module):
    rule = native_rule(kit_module, 'fixed')
    pattern = rule.find("field[@name='win.eventdata.scriptBlockText']").text
    assert literal_match(pattern, FLAT_SCRIPT)
    for text in (PAYLOAD.decode(), PAYLOAD.decode().replace('\n', '\r\n'),
                 FLAT_SCRIPT + ' ', FLAT_SCRIPT + '\n', FLAT_SCRIPT + '\x00',
                 ' ' + FLAT_SCRIPT, '# ' + FLAT_SCRIPT, '<# ' + FLAT_SCRIPT + ' #>',
                 FLAT_SCRIPT.replace("' Write-Output", "'  Write-Output"),
                 FLAT_SCRIPT + '; Get-Date', "Write-Output 'AEGIS_SAFE_DEMO_V1'",
                 FLAT_SCRIPT.replace('$PID', '$OTHER')):
        assert not literal_match(pattern, text)
    assert 'decoded script representation' in rule.findtext('description')
    assert rule.find("field[@name='win.eventdata.path']") is None


@pytest.mark.parametrize('revision', REVISIONS)
def test_native_profile_preserves_guards(kit_module, revision):
    rule = native_rule(kit_module, revision)
    assert rule.attrib == {'id': '119901', 'level': '5'}
    assert rule.findtext('if_sid') == '91816'
    assert rule.findtext('options') == 'no_email_alert'
    expected = {
        'win.system.providerName': 'Microsoft-Windows-PowerShell',
        'win.system.channel': 'Microsoft-Windows-PowerShell/Operational',
        'win.system.eventID': '4104', 'win.system.computer': 'SYNTHETIC.ENDPOINT',
        'win.eventdata.messageNumber': '1', 'win.eventdata.messageTotal': '1',
    }
    for key, value in expected.items():
        field = rule.find(f"field[@name='{key}']")
        assert field.attrib['type'] == 'pcre2'
        assert literal_match(field.text, value)
        for bad in (None, '', value + '\n', value + '0', 'OTHER'):
            assert not literal_match(field.text, bad)


@pytest.mark.parametrize('profile', [None, True, [], {}, '', 'auto', 'wazuh-eventchannel-latest'])
def test_unknown_field_profile_rejected_before_output(kit_module, tmp_path, profile):
    with pytest.raises(ValueError, match='invalid_field_profile'):
        kit_module.prepare_kit(**options(tmp_path, field_profile=profile))
    assert not (tmp_path / 'kit').exists()
    with pytest.raises(ValueError, match='invalid_field_profile'):
        kit_module.render_rule(revision='fixed', rule_id=119901, parent_sid=91816,
                               target_host='SYNTHETIC', baseline_path=r'C:\A\lab_update.ps1',
                               field_profile=profile)


def test_native_kit_records_profile_without_changing_payload_or_runner(kit_module, tmp_path):
    manifest = kit_module.prepare_kit(**options(tmp_path, field_profile=NATIVE_PROFILE))
    out = tmp_path / 'kit'
    assert manifest['field_profile'] == NATIVE_PROFILE
    assert manifest['kit_version'] == '0.3.0'  # Runner exception in `behavioral` (issue #91); runner contract moved with it.
    assert (out / 'lab_update.ps1').read_bytes() == PAYLOAD
    assert (out / 'maintenance_check.ps1').read_bytes() == PAYLOAD
    assert (out / 'Invoke-SafeDemo.ps1').read_bytes() == (ROOT / 'demos/scn-001/Invoke-SafeDemo.ps1').read_bytes()
    assert json.loads((out / 'kit.json').read_bytes()) == manifest
    for name, digest in manifest['artifact_sha256'].items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest
    catalog = json.loads((out / 'logtest-cases/catalog.json').read_bytes())
    assert catalog['field_profile'] == NATIVE_PROFILE
    assert catalog['synthetic_only'] is True
    assert catalog['input_layer'] == 'decoded_fields_json_not_native_transport'
    assert len(catalog['cases']) == 15
    fixed = ET.fromstring((out / 'fixed.xml').read_bytes()).find('rule')
    fields = {field.attrib['name']: field.text for field in fixed.findall('field')}
    behavioral = ET.fromstring((out / 'behavioral.xml').read_bytes()).find('rule')
    behavior_fields = {field.attrib['name']: field.text for field in behavioral.findall('field')}
    for case in catalog['cases']:
        event = json.loads((out / case['file']).read_bytes())
        assert event['aegis_synthetic_test_only'] is True
        values = {f'win.{section}.{key}': value
                  for section, data in event['win'].items() for key, value in data.items()}
        matched = all(literal_match(pattern, values.get(key)) for key, pattern in fields.items())
        assert matched == (case['name'] in ('original', 'renamed')), case['name']
        behavioral_hit = all(literal_match(pattern, values.get(key)) for key, pattern in behavior_fields.items())
        assert behavioral_hit == (case['expected_behavioral'] == 'demo_match'), case['name']
        if case['name'] == 'renamed':
            assert values['win.eventdata.path'] == r'C:\\AEGIS Synthetic\\maintenance_check.ps1'
            assert values['win.eventdata.scriptBlockText'] == FLAT_SCRIPT


def test_explicit_legacy_profile_retains_default_rule_bytes(kit_module):
    for revision in REVISIONS:
        args = dict(revision=revision, rule_id=119901, parent_sid=91816,
                    target_host='SYNTHETIC', baseline_path=r'C:\A\lab_update.ps1')
        assert kit_module.render_rule(**args, field_profile='decoded-json-v1') == kit_module.render_rule(**args)


def test_cli_accepts_explicit_native_profile(kit_module, tmp_path):
    result = subprocess.run([sys.executable, str(SCRIPT), '--output-dir', str(tmp_path / 'kit'),
                             '--lab-directory', r'C:\AEGIS Synthetic', '--target-host', 'SYNTHETIC',
                             '--rule-id', '119901', '--parent-sid', '91816', '--occupied-ids', 'none',
                             '--field-profile', NATIVE_PROFILE],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['status'] == 'prepared_not_executed'
    assert json.loads((tmp_path / 'kit/kit.json').read_bytes())['field_profile'] == NATIVE_PROFILE


def runner_preflight_text():
    # The block PowerShell logs for the runner's preflight is the function statement itself.
    text = (ROOT / 'demos/scn-001/Invoke-SafeDemo.ps1').read_text(encoding='ascii')
    start = text.index('function Get-AegisPreflight {')
    return text[start:text.index('\n}\n', start) + 2]


def behavioral_rules(kit_module, profile):
    return ET.fromstring(kit_module.render_rule(
        revision='behavioral', rule_id=119901, parent_sid=91816, target_host='SYNTHETIC.ENDPOINT',
        baseline_path=r'C:\AEGIS Synthetic\lab_update.ps1', field_profile=profile)).findall('rule')


def hit(rule, event):
    # Python `re` stand-in for the anchored subset used here; NOT the Wazuh/PCRE2 engine.
    return all(isinstance(event.get(f.attrib['name']), str)
               and re.search(f.text.replace(r'\z', r'\Z'), event[f.attrib['name']])
               for f in rule.findall('field'))


def fires(rules, event):
    demo, exception = rules
    if not hit(demo, event):
        return None
    return exception.attrib['id'] if hit(exception, event) else demo.attrib['id']


@pytest.mark.parametrize('profile', ['decoded-json-v1', NATIVE_PROFILE])
def test_behavioral_exempts_only_the_reviewed_runner_preflight(kit_module, profile):
    rules = behavioral_rules(kit_module, profile)
    assert [r.attrib for r in rules] == [{'id': '119901', 'level': '5'}, {'id': '119902', 'level': '0'}]
    assert rules[1].findtext('if_sid') == '119901'
    native = profile == NATIVE_PROFILE

    def event(path, text):
        base = {'win.system.providerName': 'Microsoft-Windows-PowerShell',
                'win.system.channel': 'Microsoft-Windows-PowerShell/Operational',
                'win.system.eventID': '4104', 'win.system.computer': 'SYNTHETIC.ENDPOINT',
                'win.eventdata.messageNumber': '1', 'win.eventdata.messageTotal': '1'}
        path = 'C:\\AEGIS Synthetic\\' + path
        if native:
            path, text = path.replace('\\', '\\\\'), re.sub(r'\s*\n\s*', ' ', text).strip()
        return base | {'win.eventdata.path': path, 'win.eventdata.scriptBlockText': text}

    preflight = runner_preflight_text()
    # The problem this fixes: the runner's own preflight carries both behaviors.
    assert hit(rules[0], event('Invoke-SafeDemo.ps1', preflight))
    assert fires(rules, event('Invoke-SafeDemo.ps1', preflight)) == '119902'
    for path, text in (
            ('Invoke-SafeDemo.ps1', PAYLOAD.decode()),              # payload text at the runner's path
            ('maintenance_check.ps1', preflight),                    # runner text at another path
            ('Invoke-SafeDemo.ps1x', preflight),
            ('Other\\Invoke-SafeDemo.ps1', preflight),
            ('Invoke-SafeDemo.ps1', '# x\n' + preflight),            # anchor must open the block
            ('Invoke-SafeDemo.ps1', preflight.replace("'AEGIS_WRONG_HOST'", "'OTHER'")),
            ('Invoke-SafeDemo.ps1', REWORDED)):
        assert fires(rules, event(path, text)) == '119901', (path, text[:40])


def test_runner_exception_id_must_be_free(kit_module, tmp_path):
    with pytest.raises(ValueError, match='rule_id_occupied'):
        kit_module.prepare_kit(**options(tmp_path, occupied_ids=frozenset({119902})))
    with pytest.raises(ValueError, match='invalid_rule_id'):
        kit_module.prepare_kit(**options(tmp_path, rule_id=120000))
    assert not (tmp_path / 'kit').exists()
