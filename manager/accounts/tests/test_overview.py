from django.contrib.auth.models import Permission
from django.test import Client
from django.utils import timezone

from accounts.models import AuthAudit
from control.models import Device, Job, RunnerRelease
from .helpers import AccountsCase


class OverviewTests(AccountsCase):
    def test_counts_registered_rows_without_presence_or_detection_claims_and_no_writes(self):
        device = Device.objects.create(environment_id='synthetic', certificate_sha256='a' * 64, wazuh_agent_id='synthetic', revoked=True)
        release = RunnerRelease.objects.create(scenario_path='synthetic', profile_path='synthetic', scenario_sha256='b' * 64, profile_sha256='c' * 64, runner_sha256='d' * 64, kit_sha256='e' * 64, payload_sha256='f' * 64)
        now = timezone.now()
        job = Job.objects.create(device=device, release=release, not_before=now, expires_at=now, collection_start=now, collection_end=now)
        for actor in (self.viewer, self.operator, self.admin, self.owner):
            client = self.login_human(actor)
            response = client.get('/api/v1/overview')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response['Cache-Control'], 'no-store')
            self.assertEqual(response.json(), {'registered_devices': 1, 'recorded_jobs': 1, 'recorded_releases': 1})
        job.refresh_from_db()
        self.assertEqual((job.execution_state, job.collection_state, job.envelope), ('draft', 'pending', None))
        self.assertFalse(AuthAudit.objects.exists())
        self.assertEqual(Job.objects.count(), 1)

    def test_empty_counts_and_fresh_view_authorization(self):
        self.assertEqual(Client().get('/api/v1/overview').status_code, 401)
        client = self.login_human(self.viewer)
        self.assertEqual(client.get('/api/v1/overview').json(), {'registered_devices': 0, 'recorded_jobs': 0, 'recorded_releases': 0})
        self.viewer.groups.clear()
        self.viewer.user_permissions.add(Permission.objects.get(content_type__app_label='accounts', codename='run_jobs'))
        response = client.get('/api/v1/overview')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {'error': {'code': 'permission_denied'}})
        self.assertTrue(client.get('/api/v1/auth/session').json()['authenticated'])
