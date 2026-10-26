"""HTTP authorization and closed wire boundary, with real session/CSRF handling."""
from dataclasses import asdict
from unittest.mock import patch
from django.test import Client
from django.db import connection
from django.test.utils import CaptureQueriesContext
from control.models import Job
from control.execution_contracts import canonical_bytes
from .test_execution_authority import ExecutionCase


class ExecutionApiTests(ExecutionCase):
    def test_current_http_response_uses_exact_framing_for_maximum_existing_report(self):
        dto = self.approve(); row = Job.objects.get(pk=dto.job_id)
        base = asdict(dto); base['report'] = {'padding': ''}; base['evaluation_state'] = 'evaluated'
        padding = 'x' * (4194304 - len(canonical_bytes(base)))
        Job.objects.filter(pk=row.pk).update(report={'padding': padding})
        response = self.login_human(self.operator).get('/api/v1/jobs/current')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.content), 4194304 + 8)
        self.assertTrue(response.content.startswith(b'{"job":{'))
        from control.execution_contracts import decode_contract
        self.assertEqual(decode_contract('CurrentJobDTO', response.content).job.job_id, dto.job_id)

    def test_current_job_recovers_original_committed_approval_after_expiry_and_busy_readiness(self):
        from datetime import timedelta
        request = self.approval(); dto = self.approve(request)
        client = self.login_human(self.operator)
        with patch('control.execution_services.execution_readiness', side_effect=AssertionError('recovery must not admit new work')), patch('control.execution_views.timezone.now', return_value=self.now + timedelta(minutes=10)):
            recovered = client.get('/api/v1/jobs/current')
            self.assertEqual(recovered.status_code, 200)
            self.assertEqual(recovered['Cache-Control'], 'no-store')
            self.assertEqual(recovered.json()['job']['job_id'], dto.job_id)
            replay = self.human_post(client, '/api/v1/jobs/approve', asdict(request))
            self.assertEqual(replay.status_code, 200)
            self.assertEqual(replay.json()['job_id'], dto.job_id)
        self.assertEqual(Job.objects.count(), 1)
        self.assertEqual(self.login_human(self.viewer).get('/api/v1/jobs/current').json(), {'job': None})
        self.operator.groups.clear()
        self.assertEqual(client.get('/api/v1/jobs/current').status_code, 403)
        self.assertEqual(Client().get('/api/v1/jobs/current').status_code, 401)

    def test_current_discovery_can_find_late_commit_and_authoritative_admission_states(self):
        client = self.login_human(self.operator)
        self.assertEqual(client.get('/api/v1/jobs/current').json(), {'job': None})
        dto = self.approve()
        route = '/api/v1/jobs/' + dto.job_id
        self.assertTrue(client.get('/api/v1/jobs/current').json()['job']['admission_blocked'])
        self.service.cancel_execution(self.operator, dto.job_id)
        self.assertFalse(client.get(route).json()['admission_blocked'])
        from control.models import AuditEntry
        row = Job.objects.get(pk=dto.job_id)
        for state, collection, leased, blocked in [('expired', 'pending', False, False), ('cancelled', 'pending', True, True), ('expired', 'pending', True, True), ('execution_unknown', 'pending', True, True), ('succeeded', 'collecting', True, True), ('succeeded', 'evaluated', True, False), ('execution_unknown', 'reconciled', True, False)]:
            with self.subTest(state=state, collection=collection, leased=leased):
                if leased and not AuditEntry.objects.filter(job=row, action='leased').exists():
                    self.service.audit(row, 'leased', self.device.pk)
                Job.objects.filter(pk=row.pk).update(execution_state=state, collection_state=collection)
                self.assertEqual(client.get(route).json()['admission_blocked'], blocked)

    def test_job_get_preserves_existing_nested_canonical_report(self):
        dto=self.approve(); report={'outcome':'inconclusive','evidence':[{'id':'synthetic-fixture-reference'}]}
        Job.objects.filter(pk=dto.job_id).update(report=report,collection_state='evaluated',execution_state='succeeded')
        response=self.login_human(self.viewer).get('/api/v1/jobs/'+dto.job_id)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['report'],report)
        self.assertEqual(response.json()['evaluation_state'],'evaluated')

    def test_job_report_transport_over_64k_and_oversized_approve_request(self):
        dto=self.approve()
        report={'synthetic_transport_padding':'x'*131072}
        Job.objects.filter(pk=dto.job_id).update(report=report,collection_state='evaluated',execution_state='succeeded')
        client=self.login_human(self.operator)
        response=client.get('/api/v1/jobs/'+dto.job_id)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['report'],report)
        token=client.get('/api/v1/auth/session').json()['csrf_token']
        response=client.post('/api/v1/jobs/approve',b'{}'+b' '*65535,content_type='application/json',HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code,400)

    def test_verified_machine_flow_persists_exact_bytes_before_http_response(self):
        import uuid
        from datetime import timedelta
        headers=self.certificate_headers()
        job=self.approve(); row=Job.objects.get(pk=job.job_id)
        client=Client()
        with patch('control.execution_services.execution_readiness',side_effect=self.ready):
            poll=client.post('/agent/v2/execution/poll',canonical_bytes(self.poll),content_type='application/json',**headers)
            self.assertEqual((poll.status_code,poll.content),(200,bytes(row.envelope_bytes)))
            self.assertEqual(Job.objects.get(pk=row.pk).execution_state,'leased')
            raw=canonical_bytes(asdict(self.poll)|dict(start_request_id=str(uuid.uuid4()),job_sha256=row.job_sha256))
            route='/agent/v2/execution/jobs/'+str(row.pk)+'/start'
            start=client.post(route,raw,content_type='application/json',**headers)
            self.assertEqual(start.status_code,200)
            self.assertEqual(start.content,bytes(Job.objects.get(pk=row.pk).start_ack_bytes))
            self.assertEqual(client.post(route,raw,content_type='application/json',**headers).content,start.content)
        raw=self.receipt(row)
        with patch('control.execution_views.timezone.now',return_value=self.now+timedelta(seconds=180)):
            receipt=client.post('/agent/v2/execution/receipt',raw,content_type='application/json',**headers)
        self.assertEqual(receipt.status_code,200)
        self.assertEqual(receipt.content,bytes(Job.objects.get(pk=row.pk).receipt_ack_bytes))

    def certificate_headers(self):
        from datetime import timedelta
        from urllib.parse import quote
        from cryptography.hazmat.primitives import serialization,hashes
        from cryptography.x509.oid import ExtendedKeyUsageOID
        from control.tests.test_proxy_mtls import _key,_certificate
        from control.models import Device
        key=_key(); cert=_certificate('synthetic-execution',key,'synthetic-execution',key,usage=ExtendedKeyUsageOID.CLIENT_AUTH)
        Device.objects.filter(pk=self.device.pk).update(certificate_sha256=cert.fingerprint(hashes.SHA256()).hex())
        # Bindings pin the original identity; build a new fixture before any job.
        self.device.refresh_from_db()
        from dataclasses import replace
        self.service.set_execution_binding(self.owner,str(self.device.pk),replace(self.binding_input,expected_revision=1,installation_profile_sha256='c'*64))
        from control.execution_models import DeviceExecutionBinding
        self.binding=DeviceExecutionBinding.objects.get(device=self.device,is_current=True)
        self.poll=replace(self.poll,binding_revision=2)
        self.binding_input=replace(self.binding_input,installation_profile_sha256='c'*64)
        return dict(HTTP_X_FORWARDED_PROTO='https',HTTP_X_AEGIS_CLIENT_VERIFY='SUCCESS',
            HTTP_X_AEGIS_CLIENT_CERT=quote(cert.public_bytes(serialization.Encoding.PEM).decode(),safe=''))

    def test_verified_readiness_fails_closed_and_wrong_certificate_never_looks_up_job(self):
        headers=self.certificate_headers()
        request=asdict(self.poll)|dict(installation_profile_sha256='d'*64,artifact_set_sha256=self.binding.artifact_set_sha256,
            ready=True,blocking_codes=[])
        client=Client()
        response=client.post('/agent/v2/execution/readiness',canonical_bytes(request),content_type='application/json',**headers)
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.json()['accepted'])
        # Intake acknowledgment is not Ready: the reported profile drifts from
        # the binding and this synthetic fixture has no healthy private worker.
        result=self.service.execution_readiness(str(self.device.pk),now=self.now)
        self.assertFalse(result.ready)
        self.assertIn('profile_mismatch',result.blocking_codes)
        request=asdict(self.poll)|dict(start_request_id=str(self.device.pk),job_sha256='a'*64)
        from control.models import Device
        Device.objects.filter(pk=self.device.pk).update(certificate_sha256='d'*64)
        with CaptureQueriesContext(connection) as queries:
            response=client.post('/agent/v2/execution/jobs/'+str(self.device.pk)+'/start',canonical_bytes(request),content_type='application/json',**headers)
        self.assertEqual(response.status_code,403)
        self.assertFalse(any('control_job' in item['sql'].lower() for item in queries.captured_queries))

    def test_human_csrf_fresh_permissions_statuses_and_read_never_leases(self):
        client = self.login_human(self.operator)
        payload = dict(device_id=str(self.device.pk), provider_id=self.binding.provider_id, binding_revision=1, run_label='A', rule_revision='baseline')
        self.assertEqual(client.post('/api/v1/jobs/preview', payload, content_type='application/json').status_code, 403)
        with patch('control.execution_services.execution_readiness', side_effect=self.ready):
            response = self.human_post(client, '/api/v1/jobs/preview', payload)
            self.assertEqual(response.status_code, 201)
            data = response.json()
            import uuid
            approve = dict(preview_id=data['preview_id'], preview_sha256=data['preview_sha256'], idempotency_key=str(uuid.uuid4()))
            first = self.human_post(client, '/api/v1/jobs/approve', approve)
            self.assertEqual(first.status_code, 201)
            self.assertEqual(self.human_post(client, '/api/v1/jobs/approve', approve).status_code, 200)
        result = client.get('/api/v1/jobs/'+first.json()['job_id'])
        self.assertEqual(result.status_code, 200); self.assertEqual(result['Cache-Control'], 'no-store')
        self.assertEqual(Job.objects.get().execution_state, 'queued')
        self.assertEqual(self.human_post(client, '/api/v1/jobs/'+first.json()['job_id']+'/cancel', {'extra':True}).status_code, 400)
        self.operator.groups.clear()
        self.assertEqual(self.human_post(client, '/api/v1/jobs/approve', approve).status_code, 403)

    def test_unverified_identity_and_trailing_slash_never_access_jobs(self):
        client = Client()
        for route, data in [('/agent/v2/execution/poll', asdict(self.poll)),
                ('/agent/v2/execution/receipt', {}), ('/agent/v2/execution/jobs/'+str(self.device.pk)+'/start', {})]:
            with self.subTest(route=route):
                with CaptureQueriesContext(connection) as queries:
                    response = client.post(route, canonical_bytes(data), content_type='application/json',
                        HTTP_X_FORWARDED_PROTO='https', HTTP_X_AEGIS_CLIENT_VERIFY='SUCCESS', HTTP_X_AEGIS_CLIENT_CERT='spoofed')
                self.assertEqual(response.status_code, 403)
                self.assertFalse(any('control_job' in item['sql'].lower() for item in queries.captured_queries))
            self.assertEqual(client.post(route+'/', b'{}', content_type='application/json').status_code, 404)

    def test_providers_use_reviewed_release_and_binding_get_is_closed(self):
        client = self.login_human(self.viewer)
        response = client.get('/api/v1/execution/providers')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['providers'][0]['release_id'], self.release.pk)
        response = client.get('/api/v1/execution/devices/'+str(self.device.pk))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['ready'])
        self.assertNotIn('config_path', response.content.decode())
