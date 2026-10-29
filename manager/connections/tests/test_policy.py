import unittest
import os
from pathlib import Path
import tempfile
from django.test import override_settings
from unittest.mock import patch
from connections.policy import parse_policy, load_target
from aegis_verify.connectors.wazuh.onboarding import ProbeError


class PolicyTests(unittest.TestCase):
    def test_exact_origin_index_and_closed_schema(self):
        value = {'schema_version': 1, 'targets': [{'origin': 'https://indexer.example:9200',
                 'addresses': ['192.0.2.10'], 'indices': ['wazuh-alerts-*']}]}
        targets = parse_policy(value)
        self.assertEqual(targets[0].addresses, ('192.0.2.10',))
        for bad in ({**value, 'extra': True}, {**value, 'schema_version': True},
                    {'schema_version': 1, 'targets': [{**value['targets'][0], 'addresses': ['127.0.0.1']}]},
                    {'schema_version': 1, 'targets': value['targets'] * 2}):
            with self.assertRaises(ProbeError):
                parse_policy(bad)

    def test_missing_policy_fails_closed(self):
        with patch('connections.policy.settings') as settings, self.assertRaises(ProbeError):
            settings.CONNECTION_POLICY = None
            load_target('https://indexer.example:9200', 'wazuh-alerts-*')


@unittest.skipUnless(os.name == 'posix', 'Native Linux root ownership/no-follow proof required')
class NativePolicyTests(unittest.TestCase):
    def test_untrusted_parent_and_symlink_fail_closed(self):
        from connections.policy import _read_policy
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = root/'policy.json'
            policy.write_text('{}')
            policy.chmod(0o600)
            link = root/'link.json'
            link.symlink_to(policy)
            for path in (policy,link):
                with override_settings(CONNECTION_POLICY=str(path),PRIVATE_ROOT=root/'private'), self.assertRaises(ProbeError):
                    _read_policy()

    def test_root_owned_file_gate_without_requiring_test_process_root(self):
        from connections.policy import _read_policy
        # /etc/passwd is public metadata, not credentials. Read-only use proves
        # the actual root-owner gate without modifying root-managed files.
        with override_settings(CONNECTION_POLICY='/etc/passwd',PRIVATE_ROOT='/nonexistent-aegis-private'):
            self.assertTrue(_read_policy())
            with self.assertRaises(ProbeError):
                load_target('https://indexer.example:9200','wazuh-alerts-*')
