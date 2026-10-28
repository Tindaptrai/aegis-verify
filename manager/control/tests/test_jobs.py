import tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase, override_settings
from control.signing import sign_payload
from .test_execution_authority import ExecutionCase


class LegacyExecutionFenceTests(ExecutionCase):
    def test_legacy_owner_mapping_drift_denies_claim_until_reviewed(self):
        from control.jobs import claim_job
        from control.models import Device
        legacy=Device.objects.create(environment_id='synthetic-env',certificate_sha256='f'*64,wazuh_agent_id='901')
        self.ownership.transfer_execution_ownership(self.owner,self.resource,1,str(legacy.pk),
            dict(paired_device_id=str(self.device.pk),legacy_device_id=str(legacy.pk)),
            'Explicit rollback',evidence_refs=['fixture:review'])
        Device.objects.filter(pk=legacy.pk).update(wazuh_agent_id='902')
        with self.assertRaises(PermissionError): claim_job(legacy)

    def test_paired_snapshot_cannot_use_legacy_cancel_or_approve(self):
        from control.jobs import cancel_job,approve_job
        job=self.leased()
        with self.assertRaises(ValueError): cancel_job(job.pk,self.operator)
        with self.assertRaises(ValueError): approve_job(job.pk,self.operator)

    def test_legacy_approval_respects_explicit_target_handoff(self):
        from control.jobs import approve_job
        from control.models import Device,Job
        from datetime import timedelta
        legacy=Device.objects.create(environment_id='synthetic-env',certificate_sha256='f'*64,wazuh_agent_id='901')
        self.ownership.transfer_execution_ownership(self.owner,self.resource,1,str(self.device.pk),
            dict(paired_device_id=str(self.device.pk),legacy_device_id=str(legacy.pk)),
            'Reviewed handoff',evidence_refs=['fixture:review'])
        job=Job.objects.create(device=legacy,release=self.release,not_before=self.now,expires_at=self.now+timedelta(seconds=120),
            collection_start=self.now,collection_end=self.now+timedelta(seconds=300))
        with self.assertRaises(PermissionError): approve_job(job.pk,self.operator)
        job.refresh_from_db(); self.assertIsNone(job.envelope)


class SigningTests(SimpleTestCase):
    def test_undersized_rsa_key_cannot_sign_job(self):
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.pem"
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            with override_settings(MANAGER_SIGNING_KEY=str(path)):
                with self.assertRaises(ValueError): sign_payload({"protocol":"0.1.0"})
