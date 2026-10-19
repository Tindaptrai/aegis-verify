"""Synthetic Lab B exports through the real intake/CLI/profile/engine path."""
import copy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def scenario(number):
    return next((ROOT / 'scenarios').glob('SCN-' + number + '-*.yaml'))


def cli(number, bundle):
    result = subprocess.run([sys.executable, '-m', 'aegis_verify', 'validate',
        '--scenario', str(scenario(number)), '--fixture', str(bundle),
        '--profile', str(ROOT/'scenarios/profiles'/('scn-'+number)/'profile.json'),
        '--format=json'], cwd=ROOT, capture_output=True, encoding='utf-8')
    report = json.loads(result.stdout) if result.stdout else None
    return result, report


def portable(tmp_path, number):
    src = ROOT/'tests/fixtures/cli'/('scn'+number+'-elastic-synthetic')
    target = tmp_path/'bundle'
    shutil.copytree(src, target)
    return target


def inputs(bundle):
    return json.loads((bundle/'inputs.json').read_text(encoding='utf-8'))


def save(bundle, value):
    (bundle/'inputs.json').write_text(json.dumps(value), encoding='utf-8')


def rewrite(bundle, filename, mutate):
    path = bundle/filename
    data = json.loads(path.read_text(encoding='utf-8'))
    mutate(data)
    encoded = json.dumps(data, ensure_ascii=True).encode('utf-8')+b'\n'
    path.write_bytes(encoded)
    value = inputs(bundle)
    next(e for e in value['files'] if e['path']==filename)['sha256'] = sha256(encoded).hexdigest()
    save(bundle, value)


@pytest.mark.parametrize('number', ['005', '006'])
def test_synthetic_lab_b_cli_returns_real_detected_report_with_raw_eids(number):
    bundle=ROOT/'tests/fixtures/cli'/('scn'+number+'-elastic-synthetic')
    result, report=cli(number,bundle)
    assert result.returncode==0, result.stderr
    assert report['evaluation']['final_status']=='Detected'
    assert all(x['outcome']=='satisfied' for x in report['evaluation']['assertions'])
    assert len(report['evaluation']['evidence_index'])==3
    again, replay=cli(number,bundle)
    assert again.returncode==0 and replay==report
    assert report['comparison_inputs']['context']['declarations']==[]


def test_alert_copy_alone_is_missing_telemetry(tmp_path):
    bundle=portable(tmp_path,'005');value=inputs(bundle)
    value['files']=[e for e in value['files'] if e['parser']=='elastic-security-alert-v1']
    save(bundle,value)
    result,report=cli('005',bundle)
    assert result.returncode!=0 and report['evaluation']['final_status']=='Missing telemetry'
    assert all(x['outcome']=='missing_telemetry' for x in report['evaluation']['assertions'][:2])


def test_missing_alert_is_inconclusive_without_completeness_attestation(tmp_path):
    bundle=portable(tmp_path,'005');value=inputs(bundle)
    value['files']=[e for e in value['files'] if e['parser']!='elastic-security-alert-v1']
    save(bundle,value)
    result,report=cli('005',bundle)
    assert result.returncode==3 and report['evaluation']['final_status']=='Inconclusive'
    assert report['evaluation']['assertions'][-1]['outcome']=='inconclusive'


@pytest.mark.parametrize('field,value', [('kibana.alert.rule.rule_id','different-rule'),
                                        ('kibana.alert.start','2026-01-01T00:02:01Z')])
def test_wrong_rule_or_outside_pinned_detection_window_cannot_pass(tmp_path,field,value):
    bundle=portable(tmp_path,'005')
    rewrite(bundle,'alert.json',lambda d:d['_source'].__setitem__(field,value))
    result,report=cli('005',bundle)
    assert result.returncode==3 and report['evaluation']['final_status']=='Inconclusive'


def test_mismatched_identity_fails_intake_without_source_value_leak(tmp_path):
    bundle=portable(tmp_path,'005')
    rewrite(bundle,'powershell4104.json',lambda d:d['_source']['winlog'].__setitem__('record_id','SENSITIVE_FAKE_VALUE'))
    result,report=cli('005',bundle)
    assert result.returncode==2 and report is None
    assert json.loads(result.stderr)['error']['code']=='parser_error'
    assert 'SENSITIVE_FAKE_VALUE' not in result.stderr


def test_network_allow_profile_never_turns_block_record_into_allowed_proof(tmp_path):
    bundle=portable(tmp_path,'006')
    path=bundle/'filterlog.log';path.write_bytes(path.read_bytes().replace(b',pass,',b',block,'))
    value=inputs(bundle);next(e for e in value['files'] if e['path']=='filterlog.log')['sha256']=sha256(path.read_bytes()).hexdigest();save(bundle,value)
    result,report=cli('006',bundle)
    assert result.returncode!=0
    assert report['evaluation']['final_status']!='Prevented'
    assert report['evaluation']['assertions'][-1]['outcome']!='satisfied'


def test_tampered_elastic_bytes_are_rejected_before_parsing(tmp_path):
    bundle=portable(tmp_path,'005')
    path=bundle/'sysmon1.json';path.write_bytes(path.read_bytes()+b' ')
    result,report=cli('005',bundle)
    assert result.returncode==2 and report is None
