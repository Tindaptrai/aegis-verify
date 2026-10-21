"""Real row-lock guarantee on the ephemeral PostgreSQL CI database."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
import tempfile
from threading import Barrier
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.db import connection, connections
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from control.jobs import approve_job
from control.models import Device, DispatchLock, Job, RunnerRelease


@unittest.skipUnless(connection.vendor == 'postgresql', 'Requires real PostgreSQL row locks')
class PostgreSQLDispatchTests(TransactionTestCase):
    def test_simultaneous_approvals_allow_only_one_active_job(self):
        DispatchLock.objects.get_or_create(pk=1)
        with tempfile.TemporaryDirectory(prefix='aegis-pg-synthetic-') as folder:
            root = Path(folder)
            private_key = root / 'synthetic-key.pem'
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            private_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            scenario, profile = root / 'scenario.yaml', root / 'profile.json'
            scenario.write_bytes(b'synthetic-contract-test-scenario')
            profile.write_bytes(b'synthetic-contract-test-profile')
            owner = get_user_model().objects.create_superuser('synthetic-owner')
            device = Device.objects.create(environment_id='synthetic-env',
                certificate_sha256='a' * 64, wazuh_agent_id='synthetic')
            release = RunnerRelease.objects.create(scenario_path=str(scenario), profile_path=str(profile),
                scenario_sha256=sha256(scenario.read_bytes()).hexdigest(),
                profile_sha256=sha256(profile.read_bytes()).hexdigest(), runner_sha256='b' * 64,
                kit_sha256='c' * 64, payload_sha256='d' * 64, timeout_seconds=180,
                rule_hashes={'baseline': 'e' * 64, 'behavioral': 'f' * 64})
            now = timezone.now().replace(microsecond=0)
            jobs = [Job.objects.create(device=device, release=release,
                not_before=now, expires_at=now + timedelta(seconds=120),
                collection_start=now, collection_end=now + timedelta(seconds=300),
                parameters={'run_label': 'A', 'rule_revision': 'baseline', 'rule_sha256': 'e' * 64})
                for _ in range(2)]
            barrier = Barrier(2)

            def approve(identifier):
                try:
                    actor = get_user_model().objects.get(pk=owner.pk)
                    barrier.wait(timeout=10)
                    approve_job(identifier, actor)
                    return 'approved'
                except ValueError:
                    return 'blocked'
                finally:
                    connections.close_all()

            with override_settings(MANAGER_SIGNING_KEY=str(private_key)):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    results = list(executor.map(approve, [job.pk for job in jobs]))
            self.assertCountEqual(results, ['approved', 'blocked'])
            self.assertEqual(Job.objects.filter(execution_state='queued').count(), 1)
