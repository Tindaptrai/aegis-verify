from control.execution_contracts import ExecutionError
from control.execution_services import _connection
from .test_api import ConnectionsCase
from control.tests.test_execution_authority import ExecutionFixture
from dataclasses import asdict, replace


class BoundaryTests(ConnectionsCase):
    def test_saved_and_candidate_managed_registration_rejected(self):
        from connections.models import ManagedSource
        from connections.services import is_managed_registration
        saved = self.save(self.make_draft()).json()
        source = ManagedSource.objects.get(pk=saved['id'])
        self.assertTrue(is_managed_registration(source.registration.connection_id))
        for prepared in (False, True):
            if prepared:
                self.post(saved['id']+'/prepare', {'expected_candidate_id': None})
            with self.assertRaises(ExecutionError):
                _connection(source.registration.connection_id, 1)


class BindingApiBoundaryTests(ExecutionFixture, ConnectionsCase):
    def setUp(self):
        # Both fixtures create isolated synthetic material; neither accesses a lab.
        ConnectionsCase.setUp(self)
        ExecutionFixture.setUp(self)

    def test_existing_binding_api_rejects_managed_but_retains_legacy_binding(self):
        from connections.models import ManagedSource
        from control.execution_models import DeviceExecutionBinding
        saved = self.save(self.make_draft()).json()
        source = ManagedSource.objects.get(pk=saved['id'])
        request = replace(self.binding_input, expected_revision=1,
                          wazuh_connection_id=str(source.registration.connection_id),wazuh_connection_revision=1)
        token = self.client.get('/api/v1/auth/session').json()['csrf_token']
        response = self.client.put('/api/v1/execution/devices/'+str(self.device.pk)+'/binding',
            asdict(request), content_type='application/json', HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code,409)
        binding = DeviceExecutionBinding.objects.get(device=self.device,is_current=True)
        self.assertEqual(binding.connection_id,self.connection.connection_id)
