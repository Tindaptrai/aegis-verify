"""Synthetic source responses only: never a live-lab acceptance record."""
from copy import deepcopy
from hashlib import sha256
import importlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from aegis_verify.connectors.wazuh.live import LiveError


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / 'tests/fixtures/wazuh/windows-telemetry'
JOB_ID = '00000000-0000-4000-8000-000000000001'


def page(hits, *, total=None):
    return json.dumps({'_scroll_id': 'synthetic-cursor', 'timed_out': False,
        '_shards': {'total': 1, 'successful': 1, 'failed': 0},
        'hits': {'total': {'value': len(hits) if total is None else total, 'relation': 'eq'},
                 'hits': hits}}).encode()


class SyntheticTransport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def request(self, method, path, body):
        self.calls.append((method, path, deepcopy(body)))
        if method == 'DELETE':
            return b'{"succeeded":true}'
        item = next(self.responses)
        if isinstance(item, Exception):
            raise item
        return item


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('control.collection'),
                             'first-flow collection adapter is not implemented')
        self.module = importlib.import_module('control.collection')
        self.space = tempfile.TemporaryDirectory(prefix='aegis-synthetic-collection-')
        self.addCleanup(self.space.cleanup)
        self.root = Path(self.space.name)
        self.reader_credential = secrets.token_urlsafe(24)
        self.scenario = self.root / 'scenario.yaml'
        self.profile = self.root / 'profile.json'
        self.scenario.write_bytes((ROOT / 'scenarios/SCN-001-powershell-execution.yaml').read_bytes())
        self.profile.write_bytes((FIXTURE / 'profile.json').read_bytes())

    def spec(self, **changes):
        values = dict(job_id=JOB_ID, environment_id='synthetic-env', wazuh_agent_id='901',
            start='2026-01-01T00:00:00Z', end='2026-01-01T00:10:00Z',
            bindings=({'name': 'target', 'value': 'synthetic-endpoint'},),
            scenario_path=self.scenario, profile_path=self.profile,
            scenario_sha256=sha256(self.scenario.read_bytes()).hexdigest(),
            profile_sha256=sha256(self.profile.read_bytes()).hexdigest())
        return self.module.CollectionSpec(**(values | changes))

    def connection(self):
        return self.module.WazuhConnection(endpoint='https://synthetic-indexer.example.test',
            username='synthetic-reader', password=self.reader_credential,
            ca_file=None, index='wazuh-alerts-*', collection_mode='unknown')

    def hits(self, *, detected=False):
        rows = []
        for number, name in enumerate(('sysmon1', 'powershell4104'), 1):
            value = json.loads((FIXTURE / (name + '.synthetic.json')).read_bytes())
            value.update(_id=f'synthetic-{number}', _index='wazuh-alerts-synthetic')
            if detected and name == 'powershell4104':
                value['_source']['rule']['id'] = 'synthetic-detection-only'
            rows.append(value)
        return rows

    def run_collection(self, transport, **changes):
        return self.module.collect_and_evaluate(self.spec(**changes), self.connection(),
                                                self.root / 'bundle', transport=transport)

    def test_missing_alert_preserves_bytes_eids_and_unknown_assurance(self):
        raw = page(self.hits())
        transport = SyntheticTransport([raw, page([], total=2)])
        result = self.run_collection(transport)
        self.assertEqual(result.state, 'evaluated')
        self.assertEqual(result.report['evaluation']['final_status'], 'Inconclusive')
        self.assertEqual(len(result.report['evaluation']['evidence_index']), 2)
        self.assertEqual((self.root / 'bundle/attempt-0001/response-0001.json').read_bytes(), raw)
        self.assertEqual(json.loads((self.root / 'bundle/context.json').read_bytes())['declarations'], [])
        self.assertEqual(result.summary['collection_assurance'], 'unknown')
        self.assertEqual(result.report['manager_metadata']['run_binding'], 'unknown')
        self.assertEqual(result.report['manager_metadata']['execution_receipt_is_detection_evidence'], False)
        self.assertEqual(transport.calls[0][2]['query']['bool']['filter'][0], {'term': {'agent.id': '901'}})

    def test_matching_alert_uses_real_engine_witness_and_raw_hashes(self):
        result = self.run_collection(SyntheticTransport([page(self.hits(detected=True)), page([], total=2)]))
        self.assertEqual(result.state, 'evaluated')
        self.assertEqual(result.report['evaluation']['final_status'], 'Detected')
        evidence = result.report['evaluation']['evidence_index']
        self.assertEqual(len(evidence), 2)
        evidence_ids = {entry['event_id'] for entry in evidence}
        witness = result.report['evaluation']['assertions'][2]['witness_pairs'][0]
        self.assertIn(witness['anchor_event_id'], evidence_ids)
        self.assertIn(witness['target_event_id'], evidence_ids)
        for entry in evidence:
            self.assertRegex(entry['raw_event_hash'], r'^[0-9a-f]{64}$')
        self.assertEqual(result.report['comparison_inputs']['context']['run_id'], JOB_ID)

    def test_empty_query_never_builds_or_invents_evaluable_evidence(self):
        result = self.run_collection(SyntheticTransport([page([])]))
        self.assertEqual(result.state, 'empty')
        self.assertIsNone(result.report)
        self.assertFalse((self.root / 'bundle/inputs.json').exists())
        self.assertEqual(result.summary['record_count'], 0)

    def test_source_failure_stays_collection_failure_with_safe_code(self):
        result = self.run_collection(SyntheticTransport([LiveError('connection_or_tls_failed')]))
        self.assertEqual(result.state, 'failed')
        self.assertIsNone(result.report)
        self.assertEqual(result.error_code, 'collection_failed')
        self.assertNotIn(self.reader_credential, repr(result))
        self.assertTrue((self.root / 'bundle/INCOMPLETE').exists())

    def overflow_transport(self, *, detected=True, later_failure=False):
        """174 synthetic records, with the witness in different half-open leaves."""
        anchor, target = self.hits(detected=detected)
        anchor['_source']['timestamp'] = '2026-01-01T00:00:02Z'
        target['_source']['timestamp'] = '2026-01-01T00:00:04Z'
        leaves = [[anchor], [target]]
        for side, stamp in enumerate(('2026-01-01T00:00:02Z', '2026-01-01T00:00:04Z')):
            for index in range(86):
                noise = deepcopy(anchor)
                noise['_id'] = f'synthetic-noise-{side}-{index}'
                noise['_source']['timestamp'] = stamp
                noise['_source']['data']['win']['system']['computer'] = 'synthetic-unrelated'
                leaves[side].append(noise)
        responses = [page([], total=174)]
        for rows in leaves:
            if later_failure and rows is leaves[1]:
                responses.append(LiveError('connection_or_tls_failed'))
                break
            responses.extend(page(rows[i:i + 20], total=len(rows)) for i in range(0, len(rows), 20))
            responses.append(page([], total=len(rows)))
        return SyntheticTransport(responses)

    def test_overflow_evaluates_all_174_records_once_with_cross_leaf_witness(self):
        result = self.run_collection(self.overflow_transport(), end='2026-01-01T00:00:06Z')
        self.assertEqual(result.state, 'evaluated')
        self.assertEqual(result.summary['record_count'], 174)
        self.assertEqual(result.summary['snapshot_scope'], 'per-collection')
        self.assertEqual(result.report['counts']['parsed'], 174)
        self.assertEqual(result.report['evaluation']['final_status'], 'Detected')
        witnesses = result.report['evaluation']['assertions'][2]['witness_pairs']
        self.assertEqual(len(witnesses), 1)
        by_id = {row['event_id']: row['source_ref'] for row in result.report['intake']['ledger']}
        self.assertTrue(by_id[witnesses[0]['anchor_event_id']].startswith('attempt-0002-'))
        self.assertTrue(by_id[witnesses[0]['target_event_id']].startswith('attempt-0003-'))
        self.assertEqual(result.report['comparison_inputs']['context']['declarations'], [])
        self.assertEqual(result.report['manager_metadata']['collection_assurance'], 'unknown')
        self.assertTrue((self.root / 'bundle/attempt-0001/INCOMPLETE').exists())
        self.assertEqual(len(result.report['input_fingerprints']['inputs']), 64)

    def test_overflow_missing_alert_does_not_infer_false_negative(self):
        result = self.run_collection(self.overflow_transport(detected=False), end='2026-01-01T00:00:06Z')
        self.assertEqual(result.state, 'evaluated')
        self.assertEqual(result.report['counts']['parsed'], 174)
        self.assertEqual(result.report['evaluation']['final_status'], 'Inconclusive')
        self.assertEqual(result.report['manager_metadata']['run_binding'], 'unknown')

    def test_overflow_later_failure_retains_all_attempts_and_never_reports(self):
        result = self.run_collection(self.overflow_transport(later_failure=True), end='2026-01-01T00:00:06Z')
        self.assertEqual(result.state, 'failed')
        self.assertIsNone(result.report)
        self.assertTrue((self.root / 'bundle/INCOMPLETE').exists())
        self.assertTrue((self.root / 'bundle/attempt-0002/collection.json').exists())
        self.assertFalse((self.root / 'bundle/report.json').exists())

    def test_changed_profile_is_rejected_before_contacting_source(self):
        spec = self.spec()
        self.profile.write_bytes(self.profile.read_bytes() + b' ')
        transport = SyntheticTransport([])
        result = self.module.collect_and_evaluate(spec, self.connection(), self.root / 'bundle', transport=transport)
        self.assertEqual(result.state, 'failed')
        self.assertEqual(result.error_code, 'release_pin_mismatch')
        self.assertEqual(transport.calls, [])
        self.assertFalse((self.root / 'bundle').exists())

    def test_existing_output_never_reuses_old_evidence(self):
        (self.root / 'bundle').mkdir()
        sentinel = self.root / 'bundle/inputs.json'
        sentinel.write_bytes(b'synthetic-old-evidence-sentinel')
        transport = SyntheticTransport([])
        result = self.run_collection(transport)
        self.assertEqual(result.state, 'failed')
        self.assertEqual(result.error_code, 'output_unavailable')
        self.assertEqual(transport.calls, [])
        self.assertEqual(sentinel.read_bytes(), b'synthetic-old-evidence-sentinel')

    def test_window_and_bindings_fail_closed(self):
        for changes in ({'end': '2026-01-01T00:20:00Z'},
                        {'bindings': ({'name': 'target', 'value': 'x', 'declarations': []},)},
                        {'environment_id': 'outside scope'}, {'job_id': 'not-a-uuid'}):
            with self.subTest(changes=changes):
                transport = SyntheticTransport([])
                result = self.run_collection(transport, **changes)
                self.assertEqual(result.state, 'failed')
                self.assertEqual(result.error_code, 'invalid_collection_scope')
                self.assertEqual(transport.calls, [])

    def test_connection_repr_never_exposes_credentials(self):
        self.assertNotIn(self.reader_credential, repr(self.connection()))
        self.assertNotIn('synthetic-indexer', repr(self.connection()))

    def test_private_reader_config_requires_absolute_path(self):
        with self.assertRaisesRegex(ValueError, '^invalid_private_wazuh_config$'):
            self.module.load_connection('relative.json')

    @unittest.skipUnless(os.name == 'nt', 'Windows private config ACL boundary')
    def test_reader_config_rejects_foreign_readers(self):
        config = self.root / 'reader.json'
        ca = self.root / 'synthetic-ca.pem'
        ca.write_text('synthetic-placeholder-never-used-for-a-TLS-query', encoding='utf-8')
        config.write_text(json.dumps(dict(endpoint='https://synthetic-indexer.example.test',
            username='synthetic-reader', password=self.reader_credential, ca_file=str(ca),
            index='wazuh-alerts-*', collection_mode='unknown')), encoding='utf-8')
        acl = {'owner': 'synthetic-owner', 'current': 'synthetic-owner', 'rules': [
            {'sid': 'synthetic-foreign', 'allow': True, 'rights': 2032127, 'propagate': 0, 'inherit': 0}]}
        with patch('control.collection.read_windows_acl', return_value=acl, create=True):
            with self.assertRaisesRegex(ValueError, '^invalid_private_wazuh_config$'):
                self.module.load_connection(config)
