import json

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import Client

from accounts.models import AccountSecurity, AuthAudit
from accounts.permissions import require_product_admin
from control.models import Job
from .helpers import AccountsCase


class AccountApiTests(AccountsCase):
    def write(self, client, method, route, body):
        token = client.get('/api/v1/auth/session').json()['csrf_token']
        return getattr(client, method)(route, body, content_type='application/json', HTTP_X_CSRFTOKEN=token)

    def create_body(self, username='synthetic-new'):
        return {'username': username, 'display_name': 'Synthetic User', 'password': 'synthetic-new-password',
                'capabilities': ['view'], 'is_active': True}

    def update_body(self, **changes):
        return {'display_name': 'Synthetic Updated', 'capabilities': ['view'], 'is_active': True} | changes

    def assert_error(self, response, status, code):
        self.assertEqual(response.status_code, status)
        self.assertEqual(response.json(), {'error': {'code': code}})
        self.assertEqual(response['Cache-Control'], 'no-store')

    def test_role_action_matrix(self):
        no_view = get_user_model().objects.create_user('synthetic-no-view', password='synthetic-test-password')
        no_view.user_permissions.add(Permission.objects.get(content_type__app_label='accounts', codename='manage_users'))
        for actor, allowed in ((self.owner, True), (self.admin, True), (self.operator, False), (self.viewer, False), (no_view, False)):
            client = self.login_human(actor)
            for route in ('/api/v1/users', '/api/v1/users/permissions'):
                response = client.get(route)
                self.assertEqual(response.status_code, 200 if allowed else 403)
                self.assertEqual(response['Cache-Control'], 'no-store')
            created = self.write(client, 'post', '/api/v1/users', self.create_body('synthetic-' + actor.username))
            self.assertEqual(created.status_code, 201 if allowed else 403)
            updated = self.write(client, 'put', f'/api/v1/users/{self.viewer.pk}', self.update_body())
            self.assertEqual(updated.status_code, 200 if allowed else 403)
            reset = self.write(client, 'post', f'/api/v1/users/{self.viewer.pk}/reset-password', {'new_password': 'synthetic-test-password'})
            self.assertEqual(reset.status_code, 204 if allowed else 403)

    def test_anonymous_routes_return_401_with_valid_csrf(self):
        client = Client(enforce_csrf_checks=True)
        for route in ('/api/v1/users', '/api/v1/users/permissions'):
            self.assert_error(client.get(route), 401, 'unauthenticated')
        for method, route, body in (('post', '/api/v1/users', self.create_body()),
                                    ('put', f'/api/v1/users/{self.viewer.pk}', self.update_body()),
                                    ('post', f'/api/v1/users/{self.viewer.pk}/reset-password', {'new_password': 'synthetic-password'})):
            self.assert_error(self.write(client, method, route, body), 401, 'unauthenticated')

    def test_custom_account_manager_can_create_update_reset_but_is_not_full_admin(self):
        self.viewer.user_permissions.add(Permission.objects.get(content_type__app_label='accounts', codename='manage_users'))
        self.viewer.get_all_permissions()
        client = self.login_human(self.viewer)
        response = self.write(client, 'post', '/api/v1/users', self.create_body())
        self.assertEqual(response.status_code, 201)
        user_id = response.json()['id']
        self.assertEqual(client.get('/api/v1/users').status_code, 200)
        self.assertEqual(self.write(client, 'put', f'/api/v1/users/{user_id}', self.update_body()).status_code, 200)
        self.assertEqual(self.write(client, 'post', f'/api/v1/users/{user_id}/reset-password', {'new_password': 'synthetic-reset-password'}).status_code, 204)
        with self.assertRaises(PermissionError):
            require_product_admin(self.viewer)
        self.viewer.user_permissions.clear()
        self.assert_error(client.get('/api/v1/users'), 403, 'permission_denied')

    def test_create_update_dto_and_no_secret_or_job_side_effect(self):
        client = self.login_human(self.admin)
        response = self.write(client, 'post', '/api/v1/users', self.create_body())
        self.assertEqual(response.status_code, 201)
        dto = response.json()
        self.assertEqual(set(dto), {'id', 'username', 'display_name', 'is_active', 'role', 'capabilities', 'inherited_capabilities', 'editable'})
        self.assertEqual((dto['role'], dto['capabilities'], dto['editable']), ('viewer', ['view'], True))
        response = self.write(client, 'put', f"/api/v1/users/{dto['id']}", self.update_body(capabilities=['view', 'run_jobs', 'export_evidence']))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['role'], 'operator')
        user = get_user_model().objects.get(pk=dto['id'])
        self.assertTrue(user.check_password('synthetic-new-password'))
        self.assertFalse(user.is_staff or user.is_superuser)
        self.assertNotIn('synthetic-new-password', response.content.decode())
        self.assertNotIn(user.password, json.dumps(list(AuthAudit.objects.values('before', 'after'))))
        self.assertEqual(Job.objects.count(), 0)

    def test_closed_fields_wrong_types_duplicate_keys_and_bounded_json(self):
        client = self.login_human(self.admin)
        body = self.create_body()
        bad = [body | {key: value} for key, value in [('generation', 100), ('is_staff', True), ('is_superuser', True), ('role', 'admin')]]
        bad += [body | {key: value} for key, value in [('username', 1), ('display_name', False), ('password', None), ('is_active', 1), ('capabilities', 'view')]]
        for candidate in bad:
            self.assert_error(self.write(client, 'post', '/api/v1/users', candidate), 400, 'invalid_request')
        for raw in ('{"username":"x","username":"y"}', '[]', '{"x":NaN}', ' ' * 16385):
            self.assert_error(self.write(client, 'post', '/api/v1/users', raw), 400, 'invalid_request')
        self.assert_error(self.write(client, 'put', f'/api/v1/users/{self.viewer.pk}', self.update_body(username='forged')), 400, 'invalid_request')
        self.assert_error(self.write(client, 'post', f'/api/v1/users/{self.viewer.pk}/reset-password', {'new_password': False}), 400, 'invalid_request')
        self.assert_error(self.write(client, 'post', f'/api/v1/users/{self.viewer.pk}/reset-password', {'new_password': 'synthetic-password', 'generation': 1}), 400, 'invalid_request')
        self.assertFalse(get_user_model().objects.filter(username='synthetic-new').exists())
        self.assertFalse(AuthAudit.objects.exists())

    def test_invalid_grants_and_policy_errors_are_fixed_and_transactional(self):
        client = self.login_human(self.admin)
        for grants, code in ((['unknown-secret'], 'invalid_capabilities'), (['view', 1], 'invalid_capabilities'),
                             (['view', 'view'], 'invalid_capabilities'), (['run_jobs'], 'view_required')):
            self.assert_error(self.write(client, 'post', '/api/v1/users', self.create_body() | {'capabilities': grants}), 400, code)
        self.assert_error(self.write(client, 'post', '/api/v1/users', self.create_body('viewer')), 409, 'username_exists')
        self.assert_error(self.write(client, 'put', f'/api/v1/users/{self.admin.pk}', self.update_body(is_active=False)), 409, 'self_lock')
        self.assert_error(self.write(client, 'put', '/api/v1/users/999999', self.update_body()), 400, 'user_not_found')
        self.assertFalse(AuthAudit.objects.exists())

    def test_technical_targets_are_readonly_and_no_delete_or_get_mutation(self):
        staff = get_user_model().objects.create_user('synthetic-staff', is_staff=True)
        client = self.login_human(self.admin)
        before = (AccountSecurity.objects.count(), AuthAudit.objects.count(), Job.objects.count())
        for target in (self.owner, staff):
            for method, route, body in (('put', f'/api/v1/users/{target.pk}', self.update_body()),
                                       ('post', f'/api/v1/users/{target.pk}/reset-password', {'new_password': 'synthetic-password'})):
                self.assert_error(self.write(client, method, route, body), 403, 'technical_account_readonly')
        AccountSecurity.objects.filter(user=self.viewer).delete()
        for route in ('/api/v1/users', '/api/v1/users/permissions'):
            self.assertEqual(client.get(route).status_code, 200)
        rows = client.get('/api/v1/users').json()['results']
        self.assertFalse(next(row for row in rows if row['id'] == self.owner.pk)['editable'])
        self.assertFalse(AccountSecurity.objects.filter(user=self.viewer).exists())
        self.assertEqual((AccountSecurity.objects.count(), AuthAudit.objects.count(), Job.objects.count()), (before[0] - 1, before[1], before[2]))
        token = client.get('/api/v1/auth/session').json()['csrf_token']
        self.assertEqual(client.delete(f'/api/v1/users/{self.viewer.pk}', HTTP_X_CSRFTOKEN=token).status_code, 405)
        self.assertTrue(get_user_model().objects.filter(pk=self.viewer.pk).exists())

    def test_pagination_search_stable_order_and_invalid_queries(self):
        get_user_model().objects.bulk_create([get_user_model()(username=f'synthetic-page-{number:03}') for number in range(55)])
        client = self.login_human(self.admin)
        first = client.get('/api/v1/users?q=synthetic-page-').json()
        second = client.get('/api/v1/users?q=synthetic-page-&page=2').json()
        self.assertEqual((first['count'], first['page'], first['page_size'], len(first['results'])), (55, 1, 50, 50))
        self.assertEqual([row['username'] for row in second['results']], [f'synthetic-page-{number:03}' for number in range(50, 55)])
        self.assertEqual(client.get('/api/v1/users?page=999').json()['results'], [])
        for query in ('page=0', 'page=-1', 'page=1.0', 'page=true', 'page=', 'page=' + '9' * 5000,
                      'page=1&page=2', 'q=' + 'x' * 101, 'q=a&q=b', 'page_size=999'):
            self.assert_error(client.get('/api/v1/users?' + query), 400, 'invalid_request')

    def test_permission_metadata_is_available_only_to_account_managers(self):
        client = self.login_human(self.admin)
        response = client.get('/api/v1/users/permissions')
        self.assertEqual(response.status_code, 200)
        metadata = response.json()
        self.assertEqual(len(metadata['capabilities']), 8)
        self.assertEqual({entry['key'] for entry in metadata['capabilities']}, {'view', 'run_jobs', 'import_scenarios', 'publish_scenarios', 'manage_devices', 'manage_connections', 'export_evidence', 'manage_users'})
        self.assertEqual(metadata['presets']['viewer'], ['view'])
        self.assertEqual(set(metadata['presets']['operator']), {'view', 'run_jobs', 'export_evidence'})
        self.assertTrue(all(entry['label'] for entry in metadata['capabilities']))
        self.assertTrue(all(entry['description'] for entry in metadata['capabilities']))
        self.assertTrue(metadata['inheritance_explanation'])

    def test_locked_external_inheritance_is_presented_and_cannot_be_removed(self):
        external = Group.objects.create(name='Synthetic external grants')
        external.permissions.add(Permission.objects.get(content_type__app_label='accounts', codename='run_jobs'))
        self.viewer.groups.add(external)
        client = self.login_human(self.admin)
        response = self.write(client, 'put', f'/api/v1/users/{self.viewer.pk}', self.update_body(capabilities=['view', 'run_jobs'], is_active=False))
        self.assertEqual(response.status_code, 200)
        dto = next(row for row in client.get('/api/v1/users').json()['results'] if row['id'] == self.viewer.pk)
        self.assertEqual((dto['role'], dto['capabilities'], dto['inherited_capabilities'], dto['is_active']), ('custom', ['view', 'run_jobs'], ['run_jobs'], False))
        self.assert_error(self.write(client, 'put', f'/api/v1/users/{self.viewer.pk}', self.update_body()), 409, 'inherited_capabilities_required')

    def test_last_admin_conflict_is_returned_without_audit_or_grant_change(self):
        get_user_model().objects.filter(pk=self.owner.pk).update(is_active=False)
        client = self.login_human(self.admin)
        self.assert_error(self.write(client, 'put', f'/api/v1/users/{self.admin.pk}', self.update_body()), 409, 'last_admin')
        self.assertEqual(client.get('/api/v1/auth/session').json()['user']['role'], 'admin')
        self.assertFalse(AuthAudit.objects.exists())

    def test_lock_unlock_and_password_reset_revoke_real_old_cookies(self):
        admin = self.login_human(self.admin)
        old = self.login_human(self.viewer)
        for active in (False, True):
            response = self.write(admin, 'put', f'/api/v1/users/{self.viewer.pk}', self.update_body(is_active=active))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['capabilities'], ['view'])
        self.assertFalse(old.get('/api/v1/auth/session').json()['authenticated'])
        current = self.login_human(self.viewer)
        response = self.write(admin, 'post', f'/api/v1/users/{self.viewer.pk}/reset-password', {'new_password': 'synthetic-reset-password'})
        self.assertEqual(response.status_code, 204)
        self.assertFalse(current.get('/api/v1/auth/session').json()['authenticated'])
        self.assertTrue(self.login_human(self.viewer, 'synthetic-reset-password').get('/api/v1/auth/session').json()['authenticated'])

    def test_mutations_require_real_csrf(self):
        client = self.login_human(self.admin)
        for method, route, body in (('post', '/api/v1/users', self.create_body()), ('put', f'/api/v1/users/{self.viewer.pk}', self.update_body()),
                                   ('post', f'/api/v1/users/{self.viewer.pk}/reset-password', {'new_password': 'synthetic-password'})):
            self.assert_error(getattr(client, method)(route, body, content_type='application/json'), 403, 'permission_denied')
