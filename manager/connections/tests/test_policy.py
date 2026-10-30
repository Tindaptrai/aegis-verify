import unittest
import os
from pathlib import Path
import tempfile
import json
import sys
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
    def test_untrusted_parent_fails_closed(self):
        from connections.policy import _read_policy
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = root/'policy.json'
            policy.write_text('{}')
            policy.chmod(0o600)
            root.chmod(0o777)
            with override_settings(CONNECTION_POLICY=str(policy),PRIVATE_ROOT=root/'private'), self.assertRaises(ProbeError):
                _read_policy()


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os,'geteuid') and os.geteuid() == 0,
                     'Requires root on native Linux for isolated trusted-parent policy fixtures')
class NativeRootPolicyTests(unittest.TestCase):
    """Only isolated synthetic files under /var/lib; no deployed policy changes."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='aegis-synthetic-policy-',dir='/var/lib')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root/'trusted'
        self.directory.mkdir(mode=0o700)
        self.policy = self.directory/'policy.json'
        self.origin = 'https://indexer.example:9200'
        self.index = 'wazuh-alerts-*'
        self.value = {'schema_version':1,'targets':[{'origin':self.origin,
                      'addresses':['192.0.2.10'],'indices':[self.index]}]}
        self.policy.write_text(json.dumps(self.value),encoding='utf-8')
        self.policy.chmod(0o600)
        self.settings = override_settings(CONNECTION_POLICY=str(self.policy),PRIVATE_ROOT=self.root/'private')
        self.settings.enable()
        self.addCleanup(self.settings.disable)
        # Mandatory success first: no negative test may pass merely because an
        # earlier ancestor, ownership or JSON gate prevents reaching the link.
        self.assertEqual(load_target(self.origin,self.index).origin,self.origin)

    def test_trusted_root_owned_json_policy_loads(self):
        target = load_target(self.origin,self.index)
        self.assertEqual(target.addresses,('192.0.2.10',))
        self.assertEqual(target.indices,(self.index,))

    def test_final_file_symlink_is_rejected_after_trusted_load(self):
        link = self.directory/'linked-policy.json'
        link.symlink_to(self.policy)
        with override_settings(CONNECTION_POLICY=str(link)), self.assertRaises(ProbeError):
            load_target(self.origin,self.index)
        self.assertEqual(load_target(self.origin,self.index).origin,self.origin)

    def test_parent_symlink_is_rejected_after_trusted_load(self):
        link = self.root/'linked-parent'
        link.symlink_to(self.directory,target_is_directory=True)
        with override_settings(CONNECTION_POLICY=str(link/'policy.json')), self.assertRaises(ProbeError):
            load_target(self.origin,self.index)
        self.assertEqual(load_target(self.origin,self.index).origin,self.origin)
