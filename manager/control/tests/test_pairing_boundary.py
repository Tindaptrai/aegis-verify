"""Presence identities never acquire the existing v1 execution authority."""
from django.test import TestCase
from control.jobs import claim_job
from control.models import Device, DispatchLock


class PairingBoundaryTests(TestCase):
    def test_paired_identity_cannot_claim_a_job_even_with_a_wazuh_mapping(self):
        DispatchLock.objects.get_or_create(pk=1)
        device = Device.objects.create(environment_id="synthetic", certificate_sha256="a" * 64,
                                       wazuh_agent_id="manually-mapped")
        Device.objects.filter(pk=device.pk).update(connection_kind="paired_presence")
        with self.assertRaises(PermissionError):
            claim_job(device)
