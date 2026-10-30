from datetime import timedelta
import uuid
from django.utils import timezone
from unittest.mock import patch
from .test_api import ConnectionsCase


class ServiceTests(ConnectionsCase):
    def test_unselected_list_uses_one_candidate_snapshot(self):
        from connections.services import list_sources
        saved = self.save(self.make_draft()).json()
        with patch('connections.services.candidate_id',side_effect=[None,saved['id']]) as selected:
            result = list_sources(1)
        self.assertIsNone(result['candidate_id'])
        self.assertEqual(result['results'][0]['status'],'saved')
        selected.assert_called_once()

    def test_audit_records_safe_version_and_fingerprint(self):
        from connections.models import ConnectionAudit
        import json
        draft = self.make_draft()
        saved = self.save(draft).json()
        self.post(saved['id']+'/prepare',{'expected_candidate_id':None})
        rows = list(ConnectionAudit.objects.values())
        self.assertEqual([row['version'] for row in rows],[1,1,1])
        self.assertEqual({row['action'] for row in rows},{'tested','saved','prepared'})
        self.assertTrue(all(len(row['fingerprint'])==64 for row in rows))
        encoded = json.dumps(rows,default=str)
        for value in (self.data['username'],self.data['password'],self.data['ca_pem']):
            self.assertNotIn(value,encoded)

    def test_logout_and_permission_revoke_during_io(self):
        from django.contrib.sessions.models import Session
        def logout(**kwargs):
            Session.objects.filter(session_key=self.client.session.session_key).delete()
        self.probe.side_effect = logout
        self.assertEqual(self.post('wazuh/test',self.data).status_code,403)
        self.assertEqual(self.files,{})
        self.client = self.login_human(self.admin)
        def revoke(**kwargs):
            self.admin.groups.clear()
        self.probe.side_effect = revoke
        self.assertEqual(self.post('wazuh/test',self.data).status_code,403)
        self.assertEqual(self.files,{})

    def test_publication_crash_rolls_back_registration_and_retry_is_single(self):
        from connections.models import ManagedSource
        from connections.storage import StorageError
        from control.execution_models import RegisteredExecutionConnection
        draft = self.make_draft()
        with patch.object(ManagedSource.objects,'create',side_effect=StorageError()):
            self.assertEqual(self.save(draft).status_code,503)
        self.assertEqual(RegisteredExecutionConnection.objects.count(),0)
        self.assertEqual(ManagedSource.objects.count(),0)
        self.assertEqual(self.save(draft).status_code,201)
        self.assertEqual(RegisteredExecutionConnection.objects.count(),1)

    def test_cleanup_preserves_saved_and_live_drafts(self):
        from connections.models import ConnectionDraft
        from connections.services import cleanup_expired
        saved_draft = self.make_draft()
        self.save(saved_draft)
        live = self.make_draft()
        stale = self.make_draft()
        ConnectionDraft.objects.filter(pk__in=[saved_draft['draft_id'],stale['draft_id']]).update(
            expires_at=timezone.now()-timedelta(minutes=10))
        with patch('connections.storage.cleanup') as cleanup:
            cleanup_expired()
        self.assertEqual(cleanup.call_args.args[0],{saved_draft['draft_id'],live['draft_id']})
        self.assertFalse(ConnectionDraft.objects.filter(pk=stale['draft_id']).exists())
        self.assertTrue(ConnectionDraft.objects.filter(pk=saved_draft['draft_id']).exists())

    def test_legacy_listing_never_reads_credentials(self):
        from control.execution_models import RegisteredExecutionConnection
        from connections.services import list_sources
        registration = RegisteredExecutionConnection.objects.create(revision=1, config_path='unreadable-private-path',
            config_sha256='a'*64,output_root_fingerprint='b'*64,reviewed_by=self.owner)
        with patch('builtins.open',side_effect=AssertionError('must not read config')):
            response = list_sources(1)
        self.assertEqual(response['count'],1)
        legacy = response['results'][0]
        self.assertEqual(legacy['id'],str(registration.connection_id))
        self.assertIsNone(legacy['endpoint'])
        self.assertIsNone(legacy['environment_id'])

    def test_edit_retest_rotation_is_immutable(self):
        first = self.save(self.make_draft()).json()
        second_draft = self.make_draft(source_id=first['source_id'], expected_version=1, password='new-synthetic-secret')
        competing = self.make_draft(source_id=first['source_id'], expected_version=1)
        second = self.save(second_draft)
        self.assertEqual(second.status_code, 201)
        self.assertEqual(second.json()['version'], 2)
        self.assertEqual(self.save(competing).json()['error']['code'], 'source_conflict')
        from connections.models import ManagedSource
        versions = list(ManagedSource.objects.order_by('version'))
        self.assertEqual(len(versions), 2)
        self.assertNotEqual(versions[0].registration.connection_id, versions[1].registration.connection_id)
        self.assertEqual([row.registration.revision for row in versions], [1,1])

    def test_candidate_compare_and_swap_and_expiry(self):
        from connections.models import ConnectionDraft
        from connections.services import managed_candidate
        self.assertIsNone(managed_candidate())
        a = self.save(self.make_draft()).json()
        draft_b = self.make_draft()
        b = self.save(draft_b).json()
        self.assertEqual(self.post(a['id']+'/prepare', {'expected_candidate_id': None}).status_code, 200)
        self.assertEqual(self.post(b['id']+'/prepare', {'expected_candidate_id': None}).json()['error']['code'], 'candidate_conflict')
        self.assertEqual(managed_candidate()['candidate_id'], a['id'])
        ConnectionDraft.objects.filter(pk=draft_b['draft_id']).update(expires_at=timezone.now()-timedelta(seconds=1))
        self.assertEqual(self.post(b['id']+'/prepare', {'expected_candidate_id': a['id']}).json()['error']['code'], 'draft_expired')

    def test_tampered_bytes_and_snapshot_refused(self):
        from connections.models import ConnectionDraft
        draft = self.make_draft()
        config, ca = self.files[draft['draft_id']]
        self.files[draft['draft_id']] = config+b' ', ca
        self.assertEqual(self.save(draft).json()['error']['code'], 'draft_conflict')
        self.files[draft['draft_id']] = config, ca+b' '
        self.assertEqual(self.save(draft).json()['error']['code'], 'draft_conflict')
        self.files[draft['draft_id']] = config, ca
        ConnectionDraft.objects.filter(pk=draft['draft_id']).update(summary={'name':'tampered'})
        self.assertEqual(self.save(draft).json()['error']['code'], 'draft_conflict')

    def test_pending_draft_cap(self):
        for _ in range(4):
            self.make_draft()
        self.assertEqual(self.post('wazuh/test', self.data).json()['error']['code'], 'rate_limited')

    def test_saved_history_cannot_be_mutated(self):
        from connections.models import ManagedSource
        saved = self.save(self.make_draft()).json()
        source = ManagedSource.objects.get(pk=saved['id'])
        with self.assertRaises(ValueError):
            source.save()
        with self.assertRaises(ValueError):
            ManagedSource.objects.filter(pk=source.pk).delete()
