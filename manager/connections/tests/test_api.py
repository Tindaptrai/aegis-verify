from datetime import timedelta
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import uuid
from django.test import override_settings
from django.utils import timezone
from accounts.models import AccountSecurity
from accounts.tests.helpers import AccountsCase
from .test_probe import certificate


class ConnectionsFixture:
    def setUp(self):
        self.client = self.login_human(self.owner)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.override = override_settings(PRIVATE_ROOT=Path(self.tmp.name))
        self.override.enable()
        self.addCleanup(self.override.disable)
        self.files = {}
        def create(key, config, ca):
            if str(key) in self.files:
                raise AssertionError('not exclusive')
            self.files[str(key)] = (config, ca)
        for target, options in (
            ('connections.services.run_probe', {'return_value': None}),
            ('connections.storage.create', {'side_effect': create}),
            ('connections.storage.read', {'side_effect': lambda key: self.files[str(key)]})):
            mock = patch(target, **options)
            mocked = mock.start()
            self.addCleanup(mock.stop)
            if target.endswith('run_probe'):
                self.probe = mocked
        self.data = dict(name='Synthetic Wazuh', environment_id='synthetic', endpoint='https://indexer.example:9200',
                         index='wazuh-alerts-*', username='synthetic-reader', password='synthetic-secret',
                         ca_pem=certificate(), source_id=None, expected_version=None)

    def post(self, route, data, client=None):
        return self.human_post(client or self.client, '/api/v1/connections/' + route, data)

    def make_draft(self, **changes):
        response = self.post('wazuh/test', {**self.data, **changes})
        self.assertEqual(response.status_code, 201, response.content)
        return response.json()

    def save(self, draft, key=None):
        return self.post('wazuh/save', dict(draft_id=draft['draft_id'], idempotency_key=str(key or uuid.uuid4())))


class ConnectionsCase(ConnectionsFixture, AccountsCase):
    pass


class ApiTests(ConnectionsCase):
    def test_authority_csrf_and_closed_requests(self):
        for role in (self.viewer, self.operator):
            client = self.login_human(role)
            self.assertEqual(client.get('/api/v1/connections/').status_code, 403)
            self.assertEqual(self.post('wazuh/test', self.data, client).status_code, 403)
        self.assertEqual(self.client.post('/api/v1/connections/wazuh/test', self.data,
                                         content_type='application/json').status_code, 403)
        for changes in ({'extra': 1}, {'name': 'x'*81}, {'username': 'x'*129}, {'username': 'bad:user'},
                        {'password': 'x'*1025}, {'environment_id': '../bad'}, {'expected_version': True},
                        {'ca_pem': 'x'*65537}, {'source_id': str(uuid.uuid4())}):
            self.assertEqual(self.post('wazuh/test', {**self.data, **changes}).status_code, 400)
        token = self.client.get('/api/v1/auth/session').json()['csrf_token']
        for body in ('{"name":1,"name":2}', 'x'*98305):
            self.assertEqual(self.client.post('/api/v1/connections/wazuh/test', body,
                content_type='application/json', HTTP_X_CSRFTOKEN=token).status_code, 400)
        self.probe.assert_not_called()

    def test_private_test_save_replay_and_candidate(self):
        draft = self.make_draft()
        self.assertEqual(set(draft), {'draft_id','expires_at','tested_at','checks','summary'})
        key = uuid.uuid4()
        saved = self.save(draft, key)
        self.assertEqual(saved.status_code, 201, saved.content)
        value = saved.json()
        self.assertEqual(set(value), {'id','source_id','version','name','kind','product','product_version',
                                     'environment_id','endpoint','index','ca_sha256','status','worker_state','tested_at','created_at'})
        self.assertEqual(value['worker_state'], 'waiting_configuration')
        replay = self.save(draft, key)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), value)
        self.assertEqual(self.save(draft).json()['error']['code'], 'draft_conflict')
        prepared = self.post(value['id'] + '/prepare', {'expected_candidate_id': None})
        self.assertEqual(prepared.status_code, 200, prepared.content)
        self.assertEqual(prepared.json()['source']['status'], 'candidate')
        listed = self.client.get('/api/v1/connections/')
        self.assertEqual(listed['Cache-Control'], 'no-store')
        self.assertEqual(listed.json()['candidate_id'], value['id'])
        for secret in ('synthetic-secret','synthetic-reader','config.json','ca.pem'):
            self.assertNotIn(secret, json.dumps([draft, value, listed.json()]))

    def test_stale_authority_after_probe_publishes_no_draft_files(self):
        def revoke(**kwargs):
            AccountSecurity.objects.filter(user=self.owner).update(generation=2)
        self.probe.side_effect = revoke
        response = self.post('wazuh/test', self.data)
        self.assertIn(response.status_code, (401, 403))
        self.assertEqual(self.files, {})

    def test_cross_actor_and_expired_draft(self):
        from connections.models import ConnectionDraft
        draft = self.make_draft()
        other = self.login_human(self.admin)
        response = self.post('wazuh/save', dict(draft_id=draft['draft_id'], idempotency_key=str(uuid.uuid4())), other)
        self.assertEqual(response.json()['error']['code'], 'draft_conflict')
        ConnectionDraft.objects.filter(pk=draft['draft_id']).update(expires_at=timezone.now()-timedelta(seconds=1))
        self.assertEqual(self.save(draft).json()['error']['code'], 'draft_expired')

    def test_list_query_is_closed(self):
        for query in ('?q=secret','?page=0','?page=1&page=2','?page=abc'):
            self.assertEqual(self.client.get('/api/v1/connections/'+query).status_code, 400)
