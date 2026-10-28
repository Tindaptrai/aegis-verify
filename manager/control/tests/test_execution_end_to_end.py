"""Synthetic paired client to real canonical engine; never native or lab acceptance."""
from datetime import timedelta
from hashlib import sha256
import json

from django.test import TransactionTestCase

from control import execution_services as services
from control.execution_contracts import canonical_bytes
from control.models import AuditEntry
from control.tests.test_collection import page
from control.tests.test_execution_collection import ExecutionCollectionFixture


class ExecutionEndToEndTests(ExecutionCollectionFixture,TransactionTestCase):
    def test_offline_paired_preview_to_canonical_report(self):
        job=self.succeeded()
        raw=page(self.hits(detected=True))
        self.assertTrue(self.run_one(job,[raw,page([],total=2)]))
        job.refresh_from_db(); report=job.report; bundle=self.output/str(job.pk)
        leaf=bundle/'attempt-0001'
        self.assertEqual((job.execution_state,job.collection_state),('succeeded','evaluated'))
        self.assertEqual(report['evaluation']['final_status'],'Detected')
        self.assertEqual((bundle/'attempt-0001/response-0001.json').read_bytes(),raw)
        collection=json.loads((leaf/'collection.json').read_bytes())
        self.assertEqual(collection['responses'][0]['sha256'],sha256(raw).hexdigest())
        self.assertEqual(collection['collection_assurance'],'unknown')
        inputs=json.loads((leaf/'inputs.json').read_bytes())
        evidence=report['evaluation']['evidence_index']; ids={row['event_id'] for row in evidence}
        self.assertEqual(len(ids),2)
        for row in evidence:
            ref,record=row['raw_event_ref'].split('#')
            self.assertEqual(record,'record=1')
            entry=next(item for item in inputs['files'] if item['source_ref']==ref)
            actual=(leaf/entry['path']).read_bytes()
            self.assertEqual(row['raw_event_hash'],sha256(actual).hexdigest())
            self.assertEqual(entry['sha256'],sha256(actual).hexdigest())
            self.assertEqual(json.loads(actual)['_source']['synthetic_unknown'],{'retained':'raw-only'})
            self.assertTrue(any(item['raw_event_ref']==row['raw_event_ref'] and item['event_id']==row['event_id']
                for item in report['intake']['ledger']))
        canonical=json.loads((leaf/'canonical.json').read_bytes())
        for event in canonical:
            self.assertIsNone(event['src_ip']); self.assertIsNone(event['dst_ip']); self.assertIsNone(event['file_hash'])
        for assertion in report['evaluation']['assertions']:
            self.assertTrue(set(assertion['evidence_ids'])<=ids)
            for witness in assertion['witness_pairs']:
                self.assertIn(witness['anchor_event_id'],ids); self.assertIn(witness['target_event_id'],ids)
        self.assertTrue(report['evaluation']['assertions'][2]['witness_pairs'])
        metadata=report['manager_metadata']
        self.assertEqual((metadata['execution_receipt_is_detection_evidence'],metadata['run_binding'],metadata['collection_assurance']),
            (False,'unknown','unknown'))
        self.assertEqual(report['comparison_inputs']['context']['declarations'],[])
        dto=services.get_execution_job(self.owner,str(job.pk))
        self.assertEqual(dto.evaluation_state,'evaluated')
        public=canonical_bytes(dto).decode()
        for private in (str(self.config_path),self.reader_credential,self.registered.config_sha256,
                        str(self.scenario_path),str(self.profile_path),'output_root_fingerprint'):
            self.assertNotIn(private,public)
        self.assertEqual(json.loads((bundle/'report.json').read_bytes()),report)

    def test_missing_detection_without_completeness_stays_inconclusive(self):
        job=self.succeeded()
        self.assertTrue(self.run_one(job,[page(self.hits()),page([],total=2)]))
        job.refresh_from_db()
        self.assertEqual(job.report['evaluation']['final_status'],'Inconclusive')
        self.assertEqual(job.report['comparison_inputs']['context']['declarations'],[])
        self.assertEqual(job.report['evaluation']['assertions'][2]['outcome'],'inconclusive')
        self.assertEqual(len(job.report['evaluation']['evidence_index']),2)

    def test_receipt_retry_collects_once(self):
        job=self.succeeded()
        first=bytes(job.envelope_bytes)
        self.assertEqual(services.accept_execution_receipt(self.identity,self.receipt,
            now=self.now+timedelta(seconds=181)),self.receipt_ack)
        self.assertTrue(self.run_one(job,[page([])]))
        self.assertEqual(services.accept_execution_receipt(self.identity,self.receipt,
            now=self.now+timedelta(seconds=182)),self.receipt_ack)
        self.assertFalse(self.run_one(job))
        job.refresh_from_db(); self.assertEqual(job.collection_state,'empty'); self.assertEqual(bytes(job.envelope_bytes),first)
        self.assertEqual(AuditEntry.objects.filter(job=job,action='receipt_accepted').count(),1)
        self.assertEqual(AuditEntry.objects.filter(job=job,action='collection_started').count(),1)
        self.assertEqual(AuditEntry.objects.filter(job=job,action='collection_empty').count(),1)
        self.assertEqual(len(list(self.output.iterdir())),1)
