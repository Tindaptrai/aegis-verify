"""Registry waiting must never confer collection authority or touch credentials."""
import io
import signal
from unittest.mock import patch

from django.core.management import call_command, get_commands
from django.core.management.base import CommandError
from django.test import SimpleTestCase
from .test_api import ConnectionsCase


class WaitingWorkerTests(ConnectionsCase):
    def run_once(self):
        self.assertIn('managed_connection_worker', get_commands())
        output = io.StringIO()
        call_command('managed_connection_worker', once=True, stdout=output)
        return output.getvalue()

    def test_unselected_saved_source_is_not_implicitly_selected(self):
        self.save(self.make_draft())
        self.assertEqual(self.run_once(), 'waiting_configuration:no_candidate\n')

    def test_selected_candidate_and_restart_remain_waiting_without_side_effects(self):
        from connections.models import ManagedSource, ConnectionDraft, CandidateSelection, ConnectionAudit
        from control.execution_models import RegisteredExecutionConnection, DeviceExecutionBinding, CollectionWorkerLease
        from control.models import Job
        source = self.save(self.make_draft()).json()
        self.post(source['id']+'/prepare', {'expected_candidate_id': None})
        tables = (ManagedSource, ConnectionDraft, CandidateSelection, ConnectionAudit,
                  RegisteredExecutionConnection, DeviceExecutionBinding, CollectionWorkerLease, Job)
        before = [list(model.objects.values()) for model in tables]
        with patch('control.worker.process_one', side_effect=AssertionError('collection forbidden')), \
             patch('connections.storage.read', side_effect=AssertionError('credential read forbidden')), \
             patch('socket.create_connection', side_effect=AssertionError('network forbidden')):
            self.assertEqual(self.run_once(), 'waiting_configuration:candidate_selected\n')
            self.assertEqual(self.run_once(), 'waiting_configuration:candidate_selected\n')
        self.assertEqual([list(model.objects.values()) for model in tables], before)

    def test_registration_revision_drift_is_refused(self):
        from connections.models import ManagedSource
        from control.execution_models import RegisteredExecutionConnection
        from django.db import connection
        source = self.save(self.make_draft()).json()
        self.post(source['id']+'/prepare', {'expected_candidate_id': None})
        saved = ManagedSource.objects.get(pk=source['id'])
        original = saved.registration
        changed = RegisteredExecutionConnection.objects.create(
            connection_id=original.connection_id, revision=2,
            config_path=original.config_path, config_sha256=original.config_sha256,
            output_root_path=original.output_root_path,
            output_root_fingerprint=original.output_root_fingerprint, reviewed_by=self.owner)
        # Deliberate out-of-band corruption: public APIs prohibit this rewrite.
        # Exercise the real registry lookup against drifted persisted metadata.
        with connection.cursor() as cursor:
            cursor.execute('UPDATE connections_managedsource SET registration_id = %s WHERE registration_id = %s',
                           [changed.pk, original.pk])
        with self.assertRaisesMessage(CommandError, 'registry_invalid'):
            self.run_once()


class WaitingLoopTests(SimpleTestCase):
    def test_future_active_metadata_and_invalid_registry_fail_with_fixed_code(self):
        self.assertIn('managed_connection_worker', get_commands())
        from uuid import uuid4
        valid = dict(candidate_id=str(uuid4()), source_id=str(uuid4()), version=1,
                     status='waiting_configuration', connection_id=str(uuid4()), connection_revision=1)
        invalid = [{'active_id': 'private-value'}, {'status': 'active'}, {}, 'private-value',
                   {**valid, 'active_id': str(uuid4())}, {**valid, 'status': 'active'}]
        invalid.extend({**valid, field: value} for field, values in (
            ('candidate_id', ('private-value', None)), ('source_id', ('private-value', 1)),
            ('connection_id', ('private-value', True)), ('version', (0, True, '1')),
            ('connection_revision', (0, 2, True, '1')),
        ) for value in values)
        for candidate in invalid:
            with self.subTest(candidate=candidate), \
                 patch('connections.worker.managed_candidate', return_value=candidate), \
                 self.assertRaisesRegex(CommandError, '^registry_invalid$'):
                call_command('managed_connection_worker', once=True, stdout=io.StringIO())

    def test_registry_errors_do_not_leak_and_restore_signal_handlers(self):
        self.assertIn('managed_connection_worker', get_commands())
        before = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        with patch('connections.worker.managed_candidate', side_effect=RuntimeError('private-value')), \
             self.assertRaisesRegex(CommandError, '^registry_unavailable$'):
            call_command('managed_connection_worker', once=True, stdout=io.StringIO())
        self.assertEqual({number: signal.getsignal(number) for number in before}, before)

    def test_signals_interrupt_bounded_wait_and_handlers_are_restored(self):
        self.assertIn('managed_connection_worker', get_commands())
        for number in (signal.SIGINT, signal.SIGTERM):
            before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
            waits = []
            def wait(event, timeout):
                waits.append(timeout)
                signal.getsignal(number)(number, None)
                return event.is_set()
            output = io.StringIO()
            with patch('connections.worker.managed_candidate', return_value=None), \
                 patch('threading.Event.wait', wait):
                call_command('managed_connection_worker', stdout=output)
            self.assertEqual(waits, [5])
            self.assertEqual(output.getvalue(), 'waiting_configuration:no_candidate\n')
            self.assertEqual({sig: signal.getsignal(sig) for sig in before}, before)

    def test_repeat_poll_reports_changed_selection_without_busy_loop(self):
        self.assertIn('managed_connection_worker', get_commands())
        from uuid import uuid4
        candidate = dict(candidate_id=str(uuid4()), source_id=str(uuid4()), version=1,
                         status='waiting_configuration', connection_id=str(uuid4()), connection_revision=1)
        waits = []
        def wait(event, timeout):
            waits.append(timeout)
            if len(waits) == 3:
                event.set()
            return event.is_set()
        output = io.StringIO()
        with patch('connections.worker.managed_candidate', side_effect=[None, None, candidate]), \
             patch('threading.Event.wait', wait):
            call_command('managed_connection_worker', stdout=output)
        self.assertEqual(waits, [5, 5, 5])
        self.assertEqual(output.getvalue(), 'waiting_configuration:no_candidate\nwaiting_configuration:candidate_selected\n')
