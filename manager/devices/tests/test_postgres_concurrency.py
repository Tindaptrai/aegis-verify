"""Ordered races use distinct real PostgreSQL sessions and observed lock waits.

Execute wrappers coordinate timing but always execute the production SQL. The
main connection observes pg_blocking_pids before releasing the winning row lock.
SQLite never stands in for these guarantees.
"""
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest import skipUnless
from urllib.parse import quote

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connection, connections
from django.test import RequestFactory, TransactionTestCase, override_settings

from accounts.models import AccountMutationLock
from accounts.services import update_product_user
from control.models import Device, DispatchLock, Job, RunnerRelease
from control.jobs import claim_job
from devices.archive import archive_device
from devices.issuer import initialize_issuer
from devices.models import PairingCode, EnrollmentAudit
from devices.services import create_pairing_code, enroll_device, revoke_device, receive_heartbeat, DeviceError
from .helpers import csr


@skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL row locks; SQLite cannot verify pairing races")
class PostgreSQLPairingTests(TransactionTestCase):
    def setUp(self):
        AccountMutationLock.objects.get_or_create(pk=1)
        DispatchLock.objects.get_or_create(pk=1)
        self.owner = get_user_model().objects.create_superuser("synthetic-owner", password="synthetic-password")
        self.issuer = get_user_model().objects.create_user("synthetic-issuer", password="synthetic-password")
        self.issuer.user_permissions.set(Permission.objects.filter(content_type__app_label="accounts", codename__in=("view", "manage_devices")))
        temp = tempfile.TemporaryDirectory(prefix="aegis-pg-enrollment-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        root.chmod(0o700)
        setting = override_settings(PRIVATE_ROOT=root, ENROLLMENT_CA_KEY=str(root / "key.pem"), ENROLLMENT_CA_CERT=str(root / "ca.pem"))
        setting.enable()
        self.addCleanup(setting.disable)
        initialize_issuer()
        mint = create_pairing_code(actor=self.issuer, environment_id="synthetic")
        _, pem = csr()
        self.data = {"protocol": "2.0", "pairing_code": mint["code"], "csr_pem": pem, "hostname": "synthetic",
                     "os": "linux", "architecture": "x64", "agent_version": "0.1.0"}

    def ordered_race(self, first, second, *, table):
        winner_locked, release_winner, loser_attempting = Event(), Event(), Event()
        pids, reached = {}, set()

        def worker(index, operation):
            connections.close_all()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET statement_timeout = 15000")
                    cursor.execute("SELECT pg_backend_pid()")
                    pids[index] = cursor.fetchone()[0]
                intercepted = False

                def ordered(execute, sql, params, many, context):
                    nonlocal intercepted
                    if not intercepted and table in sql and "FOR UPDATE" in sql:
                        intercepted = True
                        reached.add(index)
                        if index == 0:
                            result = execute(sql, params, many, context)
                            winner_locked.set()
                            if not release_winner.wait(15):
                                raise AssertionError("Race coordinator did not release the real row lock")
                            return result
                        if not winner_locked.wait(10):
                            raise AssertionError("Winning transaction never acquired row lock")
                        loser_attempting.set()
                    return execute(sql, params, many, context)

                with connection.execute_wrapper(ordered):
                    try:
                        operation()
                        return "committed"
                    except DeviceError as error:
                        return error.code
                    except PermissionError:
                        return "permission_denied"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker, 0, first), pool.submit(worker, 1, second)]
            try:
                self.assertTrue(loser_attempting.wait(10))
                deadline, blocked = time.monotonic() + 10, False
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT pg_blocking_pids(%s)", [pids[1]])
                        blocked = pids[0] in cursor.fetchone()[0]
                    if blocked:
                        break
                    time.sleep(0.01)
                self.assertTrue(blocked, "Second production SELECT FOR UPDATE must actually wait on the first backend")
            finally:
                release_winner.set()
            results = [f.result(timeout=20) for f in futures]
        self.assertEqual(reached, {0, 1})
        self.assertNotEqual(pids[0], pids[1])
        return results

    def test_ordered_double_redemption_consumes_once(self):
        results = self.ordered_race(lambda: enroll_device(self.data), lambda: enroll_device(self.data), table="accounts_accountmutationlock")
        self.assertEqual(results, ["committed", "pairing_denied"])
        self.assertEqual(Device.objects.count(), 1)
        self.assertIsNotNone(PairingCode.objects.get().consumed_at)
        self.assertEqual(EnrollmentAudit.objects.filter(action="device_enrolled").count(), 1)

    def demote(self):
        update_product_user(actor=self.owner, user_id=self.issuer.pk, display_name="Synthetic", capabilities=("view",), active=True)

    def test_demotion_committed_before_redemption_denies_unused_code(self):
        results = self.ordered_race(self.demote, lambda: enroll_device(self.data), table="accounts_accountmutationlock")
        self.assertEqual(results, ["committed", "pairing_denied"])
        self.assertFalse(Device.objects.exists())
        self.assertIsNone(PairingCode.objects.get().consumed_at)

    def test_redemption_committed_before_demotion_is_atomic(self):
        results = self.ordered_race(lambda: enroll_device(self.data), self.demote, table="accounts_accountmutationlock")
        self.assertEqual(results, ["committed", "committed"])
        self.assertEqual(Device.objects.count(), 1)
        self.assertIsNotNone(PairingCode.objects.get().consumed_device_id)

    def revoke_heartbeat(self, *, revoke_first):
        enrolled = enroll_device(self.data)
        request = RequestFactory().post("/agent/v2/heartbeat", HTTP_X_FORWARDED_PROTO="https", HTTP_X_AEGIS_CLIENT_VERIFY="SUCCESS",
            HTTP_X_AEGIS_CLIENT_CERT=quote(enrolled["certificate_pem"], safe=""))
        data = {"protocol": "2.0", "device_id": enrolled["device_id"], "generation": 1}
        revoke = lambda: revoke_device(actor=self.owner, device_id=enrolled["device_id"])
        heartbeat = lambda: receive_heartbeat(request=request, data=data)
        results = self.ordered_race(*( (revoke, heartbeat) if revoke_first else (heartbeat, revoke)), table="control_device")
        self.assertEqual(results, ["committed", "identity_denied" if revoke_first else "committed"])
        device = Device.objects.get()
        self.assertTrue(device.revoked)
        self.assertEqual(device.last_heartbeat_at is None, revoke_first)

    def test_revoke_wins_heartbeat_cannot_update_presence(self):
        self.revoke_heartbeat(revoke_first=True)

    def test_heartbeat_wins_then_revoke_cannot_leave_online(self):
        self.revoke_heartbeat(revoke_first=False)

    def test_double_archive_commits_exactly_once(self):
        enrolled = enroll_device(self.data)
        archive = lambda: archive_device(actor=self.owner, device_id=enrolled["device_id"])
        self.assertEqual(self.ordered_race(archive, archive, table="accounts_accountmutationlock"), ["committed", "committed"])
        device = Device.objects.get()
        self.assertTrue(device.revoked)
        self.assertIsNotNone(device.archived_at)
        self.assertEqual(EnrollmentAudit.objects.filter(action="device_archived").count(), 1)
        self.assertEqual(EnrollmentAudit.objects.filter(action="device_revoked").count(), 1)

    def archive_heartbeat(self, *, archive_first):
        enrolled = enroll_device(self.data)
        request = RequestFactory().post("/agent/v2/heartbeat", HTTP_X_FORWARDED_PROTO="https", HTTP_X_AEGIS_CLIENT_VERIFY="SUCCESS",
            HTTP_X_AEGIS_CLIENT_CERT=quote(enrolled["certificate_pem"], safe=""))
        data = {"protocol": "2.0", "device_id": enrolled["device_id"], "generation": 1}
        archive = lambda: archive_device(actor=self.owner, device_id=enrolled["device_id"])
        heartbeat = lambda: receive_heartbeat(request=request, data=data)
        results = self.ordered_race(*((archive, heartbeat) if archive_first else (heartbeat, archive)), table="control_device")
        self.assertEqual(results, ["committed", "identity_denied" if archive_first else "committed"])
        device = Device.objects.get()
        self.assertTrue(device.revoked)
        self.assertIsNotNone(device.archived_at)
        self.assertEqual(device.last_heartbeat_at is None, archive_first)
        last = device.last_heartbeat_at
        with self.assertRaises(DeviceError):
            heartbeat()
        device.refresh_from_db()
        self.assertEqual(device.last_heartbeat_at, last)

    def test_archive_wins_heartbeat_cannot_update_presence(self):
        self.archive_heartbeat(archive_first=True)

    def test_heartbeat_wins_then_archive_retains_final_presence(self):
        self.archive_heartbeat(archive_first=False)

    def archive_claim(self, *, archive_first):
        from django.utils import timezone
        enrolled = enroll_device(self.data)
        device = Device.objects.get(pk=enrolled["device_id"])
        release = RunnerRelease.objects.create()
        now = timezone.now()
        job = Job.objects.create(device=device, release=release, not_before=now, expires_at=now,
                                 collection_start=now, collection_end=now)
        archive = lambda: archive_device(actor=self.owner, device_id=device.pk)
        claim = lambda: claim_job(device)
        results = self.ordered_race(*((archive, claim) if archive_first else (claim, archive)), table="control_dispatchlock")
        self.assertEqual(results, ["committed", "permission_denied"] if archive_first else ["permission_denied", "committed"])
        job.refresh_from_db()
        device.refresh_from_db()
        self.assertEqual((job.execution_state, job.collection_state), ("draft", "pending"))
        self.assertTrue(device.revoked)
        self.assertIsNotNone(device.archived_at)

    def test_archive_wins_worker_claim_is_denied(self):
        self.archive_claim(archive_first=True)

    def test_worker_claim_then_archive_preserves_draft(self):
        self.archive_claim(archive_first=False)
