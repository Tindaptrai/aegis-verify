"""Synthetic component tests; no services, host firewall or lab files are used."""
import copy
import contextlib
import gzip
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


# Synthetic public shapes only; no owner configuration or index pattern names.
LITERAL_CONFIG_SETTINGS = (
    '# synthetic configuration; literal markers * & ! | > { } ` %\n'
    'network.host: "127.0.0.1"\nnode.name: "synthetic-literal-node"\n'
    'cluster.name: synthetic-literal-cluster\nnode.max_local_storage_nodes: 1\n'
    'plugins.security.ssl.http.enabled: true\n'
    'plugins.security.system_indices.enabled: true\n'
    'plugins.security.system_indices.indices: [".synthetic-amber*", ".synthetic-birch*", '
    '".synthetic-coral*", ".synthetic-delta*", ".synthetic-elm*", ".synthetic-fern*", '
    '".synthetic-grove*", ".synthetic-hazel*", ".synthetic-iris*", ".synthetic-jade*", '
    '".synthetic-kite*", ".synthetic-larch*"] # retained patterns * & ! | > { } ` %\n'
    'cluster.initial_master_nodes: # literal marker * is comment text\n'
    '- "synthetic-literal-node"\n'
    'plugins.security.authcz.admin_dn:\n- \'CN=synthetic-reviewer,OU=Example,O=Test\'\n'
    'plugins.security.nodes_dn:\n- "CN=synthetic-literal-node,OU=Example,O=Test"\n'
    'plugins.security.restapi.roles_enabled:\n- synthetic_role_one\n- synthetic_role_two\n'
    'plugins.security.ssl.http.pemtrustedcas_filepath: "certs/root-ca.pem"\n'
    'plugins.security.ssl.transport.pemcert_filepath: certs/indexer.pem\n'
    'plugins.security.ssl.transport.pemkey_filepath: "certs/indexer-key.pem"\n'
    'plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem\n')
LITERAL_CONFIG_TARGETS = (
    'http.bind_host: "127.0.0.1"\nhttp.port: 9200\nhttp.publish_host: 127.0.0.1\n'
    'plugins.security.ssl.http.pemcert_filepath: certs/indexer.pem\n'
    'plugins.security.ssl.http.pemkey_filepath: "certs/indexer-key.pem"\n')


def profile_dict():
    return dict(schema_version=1, hostname="indexer.example.test",
                indexer_ip="192.0.2.10", manager_ip="198.51.100.20",
                config_path="/etc/wazuh-indexer/opensearch.yml",
                ca_path="/etc/wazuh-indexer/certs/root-ca.pem",
                leaf_path="/etc/wazuh-indexer/certs/indexer.pem",
                ca_archive="/root/synthetic-certs.tar",
                ca_member="certs/root-ca.pem", key_member="certs/root-ca.key",
                expected_ca_file_sha256="a" * 64,
                expected_ca_der_sha256="b" * 64,
                expected_leaf_der_sha256="c" * 64)


def archive(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


class Components(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.c = importlib.import_module("deploy.wazuh.https_setup.contracts")
            cls.f = importlib.import_module("deploy.wazuh.https_setup.firewall")
            cls.cert = importlib.import_module("deploy.wazuh.https_setup.certificates")
        except ModuleNotFoundError:
            cls.c = cls.f = cls.cert = None

    def setUp(self):
        self.assertIsNotNone(self.c, "Task 1 components have not been implemented")
        self.raw = profile_dict()
        # Public documentation ranges are deliberately unusable in real profiles.
        self.raw.update(indexer_ip="10.23.45.10", manager_ip="10.23.45.20")
        self.p = self.c.load_profile(json.dumps(self.raw).encode())

    def reject(self, raw):
        with self.assertRaises(self.c.SetupError) as caught:
            self.c.load_profile(raw)
        self.assertEqual(str(caught.exception), "profile_invalid")

    def test_profile_roundtrip_and_frozen(self):
        self.assertEqual(self.p.as_dict(), self.raw)
        with self.assertRaises(AttributeError):
            self.p.hostname = "changed"

    def test_profile_rejects_unknown_duplicate_and_wrong_types(self):
        self.reject(json.dumps(dict(self.raw, extra=True)).encode())
        self.reject(json.dumps(self.raw).replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1').encode())
        for key, value in [("schema_version", True), ("hostname", ""), ("hostname", "x;id"),
                           ("hostname", "x%H"), ("ca_member", "../root-ca.pem"),
                           ("key_member", "/root-ca.key"), ("expected_ca_der_sha256", "g" * 64)]:
            with self.subTest(key=key, value=value):
                self.reject(json.dumps(dict(self.raw, **{key: value})).encode())

    def test_nonusable_example_and_bad_json_fail_safely(self):
        example = Path(__file__).parents[1] / "https-profile.json.example"
        self.reject(example.read_bytes())
        for raw in [b"[]", b"null", b"\xff", b"{" * 17000, b'{"schema_version": NaN}']:
            self.reject(raw)
        self.assertEqual(str(self.c.SetupError("untrusted source detail")), "setup_failed")

    def test_profile_rejects_unsafe_addresses_and_paths(self):
        for ip in ["127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.2", "192.0.2.1", "::1", self.p.manager_ip]:
            with self.subTest(ip=ip):
                self.reject(json.dumps(dict(self.raw, indexer_ip=ip)).encode())
        for key, path in [("config_path", "/tmp/opensearch.yml"), ("ca_path", "/etc/wazuh-indexer/../ca"),
                          ("leaf_path", "/etc/wazuh-indexer/aegis-http/tls/indexer-http.pem"),
                          ("ca_archive", "/usr/local/lib/aegis-wazuh-https/certs.tar"),
                          ("ca_archive", "relative.tar"), ("ca_archive", "/root/x\n.tar")]:
            with self.subTest(key=key, path=path):
                self.reject(json.dumps(dict(self.raw, **{key: path})).encode())

    def test_config_preserves_unrelated_bytes_and_is_idempotent(self):
        raw = (b"# synthetic\r\nnetwork.host: 127.0.0.1\r\ncluster.name: 'test' # unchanged\r\n"
               b"node.name: test\r\nhttp.bind_host: 127.0.0.1\r\nhttp.port: 9200\r\n"
               b"http.publish_host: 127.0.0.1\r\nplugins.security.ssl.http.pemcert_filepath: old.pem\r\n"
               b"plugins.security.ssl.http.pemkey_filepath: old-key.pem\r\n"
               b"plugins.security.ssl.transport.pemkey_filepath: transport.pem\r\n")
        expected = raw.replace(b"http.bind_host: 127.0.0.1", b'http.bind_host: ["127.0.0.1", "10.23.45.10"]')
        expected = expected.replace(b"http.publish_host: 127.0.0.1", b'http.publish_host: "127.0.0.1"')
        expected = expected.replace(b"pemcert_filepath: old.pem", b'pemcert_filepath: "/etc/wazuh-indexer/aegis-http/tls/indexer-http.pem"')
        expected = expected.replace(b"pemkey_filepath: old-key.pem", b'pemkey_filepath: "/etc/wazuh-indexer/aegis-http/tls/indexer-http-key.pem"')
        patched = self.c.patch_http_config(raw, self.p)
        self.assertEqual(patched, expected)
        self.assertEqual(self.c.patch_http_config(patched, self.p), patched)
        self.assertNotIn(b"http.host:", patched)

    def test_config_adds_missing_fields_and_rejects_ambiguous_yaml(self):
        raw = b"network.host: 127.0.0.1\ncluster.initial_master_nodes:\n  - test\n"
        self.assertTrue(self.c.patch_http_config(raw, self.p).startswith(raw))
        for raw in [b"http.host: x\nhttp.host: y\n", b"http:\n  host: x\n", b"http.host: &x y\n",
                    b"'http.host': x\n", b"network.host: *alias\n", b"---\nhttp.host: x\n",
                    b"http.host: |\n  x\n", b"plugins:\n  security: x\n"]:
            with self.subTest(raw=raw), self.assertRaises(self.c.SetupError):
                self.c.patch_http_config(raw, self.p)

    def test_config_preserves_quoted_wildcard_lists_with_public_scalar_shapes(self):
        patched_targets = (
            'http.bind_host: ["127.0.0.1", "10.23.45.10"]\nhttp.port: 9200\n'
            'http.publish_host: "127.0.0.1"\n'
            'plugins.security.ssl.http.pemcert_filepath: "/etc/wazuh-indexer/aegis-http/tls/indexer-http.pem"\n'
            'plugins.security.ssl.http.pemkey_filepath: "/etc/wazuh-indexer/aegis-http/tls/indexer-http-key.pem"\n')
        for newline in ('\n', '\r\n'):
            for final_newline in (True, False):
                with self.subTest(newline=newline, final_newline=final_newline):
                    raw = (LITERAL_CONFIG_SETTINGS + LITERAL_CONFIG_TARGETS).replace('\n', newline).encode()
                    expected = (LITERAL_CONFIG_SETTINGS + patched_targets).replace('\n', newline).encode()
                    if not final_newline:
                        raw = raw.removesuffix(newline.encode())
                        expected = expected.removesuffix(newline.encode())
                    patched = self.c.patch_http_config(raw, self.p)
                    self.assertEqual(patched, expected)
                    self.assertEqual(self.c.patch_http_config(patched, self.p), patched)

    def test_config_preserves_literal_markers_and_comments_after_complete_values(self):
        values = (
            b'"* & ! | > { } ` % : # literal"',
            b"'* & ! | > { } ` % : # it''s literal'",
            b'["*", "&", "!", "|", ">", "{", "}", "`", "%", "name:#fragment"]',
            b'["escaped \\\"quote\\\"", "slash\\\\path", 7, true, false]',
            b'plain', b'"quoted"', b"'quoted'", b'["flat", 1, true]',
        )
        comment = b' # retained * & ! | > { } ` % : # comment'
        for value in values:
            for trailing in (b'', comment):
                raw = b'unknown.literal: ' + value + trailing + b'\n'
                with self.subTest(raw=raw):
                    patched = self.c.patch_http_config(raw, self.p)
                    self.assertTrue(patched.startswith(raw))
                    self.assertEqual(self.c.patch_http_config(patched, self.p), patched)
        raw = b'items:' + comment + b'\n- "literal*"\nnext: plain' + comment + b'\n'
        self.assertTrue(self.c.patch_http_config(raw, self.p).startswith(raw))
        for raw in (b'items:' + comment + b'\n', b'items:' + comment + b'\nnext: plain\n',
                    b'http.port:' + comment + b'\n- 9200\n'):
            with self.subTest(raw=raw), self.assertRaisesRegex(self.c.SetupError, 'config_unsupported'):
                self.c.patch_http_config(raw, self.p)

    def test_config_refuses_active_yaml_syntax_and_partially_consumed_literals(self):
        values = (
            b'*alias', b'&anchor scalar', b'!tag scalar', b'!!str scalar', b'|', b'>',
            b'{"nested": "map"}', b'[["nested"]]', b'[{"nested": "map"}]',
            b'[*alias]', b'["literal*", *alias]', b'[&anchor "scalar"]', b'[!tag "scalar"]',
            b'"literal*" *alias', b'"literal*" &anchor', b'"literal*" !tag',
            b'["literal*"] *alias', b'["literal*"] &anchor', b'["literal*"] !tag',
            b"'literal*' *alias", b'"literal*" trailing', b'["literal*"] trailing',
            b'"unclosed*', b"'unclosed*", b'["unclosed*"', b'["x",]', b'"bad\\q*"',
            b'[null]', b'[1.5]', b'[NaN]', b'[Infinity]', b'[true, {"x": 1}]',
            b'plain*', b'plain&', b'plain!', b'plain|', b'plain>', b'plain{',
            b'plain}', b'plain`', b'plain%', b'%YAML 1.2',
        )
        for value in values:
            raw = b'unknown.literal: ' + value + b'\n'
            with self.subTest(raw=raw), self.assertRaisesRegex(self.c.SetupError, 'config_unsupported'):
                self.c.patch_http_config(raw, self.p)
        for raw in (b'%YAML 1.2\nnode.name: "literal*"\n', b'---\nnode.name: "literal*"\n',
                    b'"node.name": "literal*"\n', b"'node.name': 'literal*'\n",
                    b'node.name: "literal*"\nnode.name: "again*"\n',
                    b'node.name: "literal*"\nnode: "collision*"\n',
                    b'node: "literal*"\nnode.name: "collision*"\n'):
            with self.subTest(raw=raw), self.assertRaisesRegex(self.c.SetupError, 'config_unsupported'):
                self.c.patch_http_config(raw, self.p)

    def test_config_quoted_wildcards_do_not_bypass_http_target_admission(self):
        for key, value in ((b'http.bind_host', b'"*"'), (b'http.bind_host', b'["127.0.0.1", "*"]'),
                           (b'http.publish_host', b"'*'"), (b'http.publish_host', b'["*"]'),
                           (b'http.port', b'"*"'), (b'http.port', b'["*"]')):
            with self.subTest(key=key, value=value), self.assertRaisesRegex(self.c.SetupError, 'config_unsupported'):
                self.c.patch_http_config(key + b': ' + value + b'\n', self.p)

    def test_config_preserves_public_scalar_block_lists_in_both_indentation_styles(self):
        original_targets = (
            'http.bind_host: 127.0.0.1\nhttp.port: 9200\nhttp.publish_host: 127.0.0.1\n'
            'plugins.security.ssl.http.pemcert_filepath: old.pem\n'
            'plugins.security.ssl.http.pemkey_filepath: old-key.pem\n')
        patched_targets = (
            'http.bind_host: ["127.0.0.1", "10.23.45.10"]\nhttp.port: 9200\n'
            'http.publish_host: "127.0.0.1"\n'
            'plugins.security.ssl.http.pemcert_filepath: "/etc/wazuh-indexer/aegis-http/tls/indexer-http.pem"\n'
            'plugins.security.ssl.http.pemkey_filepath: "/etc/wazuh-indexer/aegis-http/tls/indexer-http-key.pem"\n')
        for indents in ((0, 0, 0, 0), (2, 2, 2, 2), (0, 2, 4, 0), (3, 0, 1, 4)):
            a, b, c, d = (" " * width for width in indents)
            lists = (
                'cluster.initial_master_nodes: # synthetic list\n'
                f'# before first item\n{a}- "synthetic-node" # unchanged\n\n'
                'plugins.security.authcz.admin_dn:\n'
                f"{b}- 'CN=synthetic-admin,OU=Example,O=Test'\n"
                'plugins.security.nodes_dn:\n'
                f'{c}- "CN=synthetic-node,OU=Example,O=Test"\n'
                'plugins.security.restapi.roles_enabled:\n'
                f'{d}- synthetic_role_one\n  # between items\n\n{d}- "synthetic_role_two"\n')
            prefix = '# synthetic configuration\nnode.name: synthetic-node\ncluster.name: synthetic-cluster\n'
            for newline in ('\n', '\r\n'):
                for final_newline in (True, False):
                    with self.subTest(indents=indents, newline=newline, final_newline=final_newline):
                        raw = (prefix + original_targets + lists).replace('\n', newline).encode()
                        expected = (prefix + patched_targets + lists).replace('\n', newline).encode()
                        untouched_lists = lists.replace('\n', newline).encode()
                        if not final_newline:
                            raw = raw.removesuffix(newline.encode())
                            expected = expected.removesuffix(newline.encode())
                            untouched_lists = untouched_lists.removesuffix(newline.encode())
                        patched = self.c.patch_http_config(raw, self.p)
                        self.assertEqual(patched, expected)
                        self.assertTrue(patched.endswith(untouched_lists))
                        self.assertEqual(self.c.patch_http_config(patched, self.p), patched)

    def test_config_indentless_list_without_final_newline_adds_missing_targets(self):
        raw = b'cluster.initial_master_nodes:\n- synthetic-node'
        expected = raw + (
            b'\nhttp.bind_host: ["127.0.0.1", "10.23.45.10"]\nhttp.port: 9200\n'
            b'http.publish_host: "127.0.0.1"\n'
            b'plugins.security.ssl.http.pemcert_filepath: "/etc/wazuh-indexer/aegis-http/tls/indexer-http.pem"\n'
            b'plugins.security.ssl.http.pemkey_filepath: "/etc/wazuh-indexer/aegis-http/tls/indexer-http-key.pem"\n')
        self.assertEqual(self.c.patch_http_config(raw, self.p), expected)
        self.assertEqual(self.c.patch_http_config(expected, self.p), expected)

    def test_config_block_lists_refuse_empty_orphan_mixed_and_nested_entries(self):
        cases = [
            b'items:\n', b'items:\n# empty\n\n', b'items:\nnext: scalar\n',
            b'items:\n- first\nempty:\n', b'items:\n- first\nempty:\nnext: scalar\n',
            b'- orphan\n', b'node.name: synthetic\n- orphan\n', b'items: ["inline"]\n- orphan\n',
            b'items:\n- first\n  - second\n', b'items:\n  - first\n- second\n',
            b'items:\n  - first\n    - second\n', b'items:\n    - first\n  - second\n',
            b'items:\n  mapping: scalar\n', b'items:\n- name: scalar\n',
            b'items:\n-\n', b'items:\n- \n', b'items:\n- # empty\n',
            b'items:\n- -\n', b'items:\n- :\n', b'items:\n- - nested\n',
            b'items:\n  - -\n', b'items:\n  - :\n',
            b'items:\n  - - # empty sequence\n', b'items:\n  - : # empty mapping\n',
            b'items:\n- ["nested"]\n', b'items:\n- {"nested": "map"}\n',
            b'items:\n- *alias\n', b'items:\n- &anchor scalar\n', b'items:\n- !!str scalar\n',
            b'items:\n- %YAML 1.2\n', b'items:\n- |\n  folded\n',
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaisesRegex(self.c.SetupError, 'config_unsupported'):
                self.c.patch_http_config(raw, self.p)

    def test_config_block_lists_preserve_quoted_collection_indicator_scalars(self):
        for indent in (b'', b'  '):
            raw = b'items:\n' + indent + b'- "-"\n' + indent + b"- ':'\n"
            self.assertTrue(self.c.patch_http_config(raw, self.p).startswith(raw))

    def test_config_block_lists_refuse_unquoted_terminal_mapping_colons(self):
        for indent in (b'', b'  '):
            for value in (b'name:', b'name: # empty mapping value'):
                raw = b'items:\n' + indent + b'- ' + value + b'\n'
                with self.subTest(raw=raw), self.assertRaisesRegex(self.c.SetupError, 'config_unsupported'):
                    self.c.patch_http_config(raw, self.p)

    def test_config_block_lists_preserve_quoted_and_embedded_colons(self):
        for indent in (b'', b'  '):
            for value in (b'"name:"', b"'name:'", b'name:value',
                          b'"name:#fragment"', b"'name:#fragment'"):
                for comment in (b'', b' # retained comment'):
                    raw = b'items:\n' + indent + b'- ' + value + comment + b'\n'
                    with self.subTest(raw=raw):
                        patched = self.c.patch_http_config(raw, self.p)
                        self.assertTrue(patched.startswith(raw))
                        self.assertEqual(self.c.patch_http_config(patched, self.p), patched)

    def test_config_indentless_lists_keep_target_and_network_refusals(self):
        prefix = b'cluster.initial_master_nodes:\n- synthetic-node\n'
        for bad in [b'cluster.initial_master_nodes: duplicate\n', b'cluster: collision\n',
                    b'cluster.initial_master_nodes.child: collision\n', b'http.bind_host:\n- 127.0.0.1\n',
                    b'http.port:\n- 9200\n', b'http.publish_host:\n- 127.0.0.1\n',
                    b'plugins.security.ssl.http.pemcert_filepath:\n- old.pem\n',
                    b'plugins.security.ssl.http.pemkey_filepath:\n- old-key.pem\n',
                    b'http.host: 127.0.0.1\n', b'http.bind_host: 0.0.0.0\n',
                    b'http.port: 9201\n', b'http.publish_host: 0.0.0.0\n',
                    b'http.publish_port: 9201\n', b'http.bind_host.name: collision\n']:
            with self.subTest(bad=bad), self.assertRaisesRegex(self.c.SetupError, 'config_unsupported'):
                self.c.patch_http_config(prefix + bad, self.p)

    def test_config_refuses_conflicting_network_overrides_and_invalid_scalars(self):
        for raw in [b"http.host: 127.0.0.1\n", b"http.bind_host: 0.0.0.0\n", b"http.port: 9201\n",
                    b"http.publish_port: 9201\n", b"http.publish_host: 0.0.0.0\n",
                    b"http.bind_host.name: x\n", b"node.name: broken: yaml\n",
                    b'node.name: "unclosed\n', b"node.name: [broken\n"]:
            with self.subTest(raw=raw), self.assertRaises(self.c.SetupError):
                self.c.patch_http_config(raw, self.p)
        raw = b'network.host: 127.0.0.1\nplugins.security.authcz.admin_dn:\n  - "CN=admin,OU=Synthetic,O=Test"\n'
        self.assertTrue(self.c.patch_http_config(raw, self.p).startswith(raw))

    def test_archive_reads_only_exact_regular_members(self):
        ca = b"synthetic public ca"
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(ca).hexdigest())).encode())
        raw = archive([("certs/root-ca.pem", ca, tarfile.REGTYPE), ("certs/root-ca.key", b"synthetic key", tarfile.REGTYPE), ("password.txt", b"unread", tarfile.REGTYPE)])
        self.assertEqual(self.c.archive_ca_members(raw, p), (ca, b"synthetic key"))
        with self.assertRaises(self.c.SetupError):
            self.c.archive_ca_members(raw, self.p)

    def test_archive_rejects_links_duplicates_traversal_and_limits(self):
        base = [("certs/root-ca.pem", b"ca", tarfile.REGTYPE), ("certs/root-ca.key", b"key", tarfile.REGTYPE)]
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(b"ca").hexdigest())).encode())
        safe = archive(base)
        self.assertEqual(self.c.archive_ca_members(safe, p), (b"ca", b"key"))
        for extra in [("link", b"", tarfile.SYMTYPE), ("link", b"", tarfile.LNKTYPE),
                      ("../outside", b"", tarfile.REGTYPE), ("/outside", b"", tarfile.REGTYPE),
                      ("certs/root-ca.pem", b"ca", tarfile.REGTYPE),
                      ("oversized", b"x" * (1024 * 1024 + 1), tarfile.REGTYPE)]:
            with self.subTest(extra=extra[0]), self.assertRaises(self.c.SetupError):
                self.c.archive_ca_members(archive(base + [extra]), p)
        with self.assertRaises(self.c.SetupError):
            self.c.archive_ca_members(safe + b"\0" * (32 * 1024 * 1024 + 512 - len(safe)), p)

    def test_archive_rejects_hidden_concatenated_duplicates_and_compression_bombs(self):
        import gzip
        ca = b"synthetic ca"
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(ca).hexdigest())).encode())
        base = [("certs/root-ca.pem", ca, tarfile.REGTYPE), ("certs/root-ca.key", b"key", tarfile.REGTYPE)]
        safe = archive(base)
        self.assertEqual(self.c.archive_ca_members(safe, p), (ca, b"key"))
        self.assertEqual(self.c.archive_ca_members(gzip.compress(safe), p), (ca, b"key"))
        oversized = safe + b"\0" * (32 * 1024 * 1024 + 512 - len(safe))
        for bad in [safe + safe, gzip.compress(oversized),
                    archive(base + [(f"member-{n}", b"x", tarfile.REGTYPE) for n in range(127)])]:
            with self.subTest(size=len(bad)), self.assertRaises(self.c.SetupError):
                self.c.archive_ca_members(bad, p)

    def test_seekable_intake_never_reads_unrelated_member_bodies(self):
        reader = getattr(self.c, "read_archive_ca_members", None)
        self.assertIsNotNone(reader, "strict seekable archive intake is missing")
        base = [("password.txt", b"x" * 512, tarfile.REGTYPE),
                ("certs/root-ca.pem", b"ca", tarfile.REGTYPE),
                ("unrelated-key.pem", b"y" * 512, tarfile.REGTYPE),
                ("certs/root-ca.key", b"key", tarfile.REGTYPE),
                ("trailing-password.txt", b"z" * 512, tarfile.REGTYPE)]
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(b"ca").hexdigest())).encode())

        class BodyGuard(io.BytesIO):
            def read(self, size=-1):
                start = self.tell()
                end = len(self.getbuffer()) if size < 0 else start + size
                for left, right in [(512, 1024), (2560, 3072), (4608, 5120)]:
                    if start < right and end > left:
                        raise AssertionError("read overlaps unrelated synthetic body")
                return super().read(size)

        source = BodyGuard(archive(base))
        source.seek(5)
        self.assertEqual(reader(source, p), (b"ca", b"key"))
        self.assertFalse(source.closed)
        self.assertEqual(source.tell(), 5)

    def test_seekable_intake_rejects_single_defect_archives_with_valid_targets(self):
        import gzip
        reader = getattr(self.c, "read_archive_ca_members", None)
        self.assertIsNotNone(reader, "strict seekable archive intake is missing")
        base = [("certs/root-ca.pem", b"ca", tarfile.REGTYPE), ("certs/root-ca.key", b"key", tarfile.REGTYPE)]
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(b"ca").hexdigest())).encode())
        safe = archive(base)
        self.assertEqual(reader(io.BytesIO(safe), p), (b"ca", b"key"))
        defects = {
            "compression": gzip.compress(safe),
            "hidden duplicate archive": safe + safe,
            "hidden new member": safe + archive([("hidden", b"hidden", tarfile.REGTYPE)]),
            "nonzero trailer": safe + b"x" * 512,
            "short trailer": safe + b"x",
            "missing end marker": safe[:2048],
            "symlink": archive(base + [("link", b"", tarfile.SYMTYPE)]),
            "hardlink": archive(base + [("link", b"", tarfile.LNKTYPE)]),
            "duplicate": archive(base + [base[0]]),
            "parent traversal": archive(base + [("../outside", b"x", tarfile.REGTYPE)]),
            "absolute": archive(base + [("/outside", b"x", tarfile.REGTYPE)]),
            "member size": archive(base + [("oversized", b"x" * (1024 * 1024 + 1), tarfile.REGTYPE)]),
            "member count": archive(base + [(f"member-{n}", b"x", tarfile.REGTYPE) for n in range(127)]),
            "archive size": safe + b"\0" * (32 * 1024 * 1024 + 512 - len(safe)),
            "extension record": archive(base + [("pax", b"", tarfile.XHDTYPE)]),
        }
        for name, raw in defects.items():
            with self.subTest(defect=name), self.assertRaises(self.c.SetupError) as caught:
                reader(io.BytesIO(raw), p)
            self.assertEqual(str(caught.exception), "archive_invalid")

    def test_seekable_intake_refuses_buffered_and_nonseekable_sources(self):
        reader = getattr(self.c, "read_archive_ca_members", None)
        self.assertIsNotNone(reader, "strict seekable archive intake is missing")
        base = [("certs/root-ca.pem", b"ca", tarfile.REGTYPE), ("certs/root-ca.key", b"key", tarfile.REGTYPE)]
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(b"ca").hexdigest())).encode())
        self.assertEqual(reader(io.BytesIO(archive(base)), p), (b"ca", b"key"))
        class Nonseekable(io.BytesIO):
            def seekable(self):
                return False
        for source in [Nonseekable(archive(base)), io.BufferedReader(io.BytesIO(archive(base)))]:
            with source, self.assertRaises(self.c.SetupError):
                reader(source, p)

    def test_vendor_gzip_selects_only_targets_with_bounded_reads_and_no_output_or_extraction(self):
        reader = getattr(self.c, "read_vendor_ca_archive", None)
        self.assertIsNotNone(reader, "bounded vendor archive intake is missing")
        marker = b"SYNTHETIC_UNRELATED_CREDENTIAL_DO_NOT_RETAIN"
        base = [("password.txt", marker * 4096, tarfile.REGTYPE),
                ("certs/root-ca.pem", b"ca", tarfile.REGTYPE),
                ("other-key.pem", marker * 4096, tarfile.REGTYPE),
                ("certs/root-ca.key", b"key", tarfile.REGTYPE)]
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(b"ca").hexdigest())).encode())

        class BoundedSource(io.BytesIO):
            def read(self, size=-1):
                if not 0 < size <= 65536:
                    raise AssertionError("source read must be explicit and bounded")
                return super().read(size)

        source = BoundedSource(gzip.compress(archive(base)))
        source.seek(7)
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            before = Path.cwd()
            try:
                os.chdir(temporary)
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    actual = reader(source, p)
                self.assertEqual(list(Path(temporary).iterdir()), [])
            finally:
                os.chdir(before)
        self.assertEqual(actual, (b"ca", b"key"))
        self.assertNotIn(marker, b"".join(actual))
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(source.tell(), 7)
        self.assertFalse(source.closed)

    def test_vendor_intake_dispatches_plain_tar_and_rejects_unsafe_gzip_members(self):
        reader = getattr(self.c, "read_vendor_ca_archive", None)
        self.assertIsNotNone(reader, "bounded vendor archive intake is missing")
        base = [("certs/root-ca.pem", b"ca", tarfile.REGTYPE), ("certs/root-ca.key", b"key", tarfile.REGTYPE)]
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(b"ca").hexdigest())).encode())
        safe = archive(base)
        self.assertEqual(reader(io.BytesIO(safe), p), (b"ca", b"key"))
        self.assertEqual(reader(io.BytesIO(gzip.compress(safe)), p), (b"ca", b"key"))
        for name, extra in [
                ("symlink", ("link", b"", tarfile.SYMTYPE)),
                ("hardlink", ("link", b"", tarfile.LNKTYPE)),
                ("device", ("device", b"", tarfile.CHRTYPE)),
                ("duplicate", base[0]),
                ("parent", ("../outside", b"x", tarfile.REGTYPE)),
                ("absolute", ("/outside", b"x", tarfile.REGTYPE)),
                ("unsafe", ("dollar$name", b"x", tarfile.REGTYPE)),
                ("oversized", ("big", b"x" * (1024 * 1024 + 1), tarfile.REGTYPE)),
                ("extension", ("pax", b"", tarfile.XHDTYPE)),
                ("longname", ("longname", b"", tarfile.GNUTYPE_LONGNAME)),
                ("sparse", ("sparse", b"", tarfile.GNUTYPE_SPARSE))]:
            with self.subTest(defect=name), self.assertRaises(self.c.SetupError) as caught:
                reader(io.BytesIO(gzip.compress(archive(base + [extra]))), p)
            self.assertEqual(str(caught.exception), "archive_invalid")

    def test_vendor_gzip_does_not_accumulate_unselected_plaintext(self):
        import tracemalloc
        reader = getattr(self.c, "read_vendor_ca_archive", None)
        self.assertIsNotNone(reader, "bounded vendor archive intake is missing")
        base = [(f"unrelated-{n}", b"x" * (1024 * 1024), tarfile.REGTYPE) for n in range(20)]
        base.extend([("certs/root-ca.pem", b"ca", tarfile.REGTYPE), ("certs/root-ca.key", b"key", tarfile.REGTYPE)])
        compressed = gzip.compress(archive(base))
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(b"ca").hexdigest())).encode())
        # Fixture construction is outside tracing; measure only real intake.
        source = io.BytesIO(compressed)
        tracemalloc.start()
        try:
            result = reader(source, p)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(result, (b"ca", b"key"))
        self.assertLess(peak, 4 * 1024 * 1024, "intake accumulated unselected decoded data")

    def test_vendor_gzip_rejects_bombs_counts_bad_checksums_and_hidden_trailers(self):
        reader = getattr(self.c, "read_vendor_ca_archive", None)
        self.assertIsNotNone(reader, "bounded vendor archive intake is missing")
        base = [("certs/root-ca.pem", b"ca", tarfile.REGTYPE), ("certs/root-ca.key", b"key", tarfile.REGTYPE)]
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(b"ca").hexdigest())).encode())
        safe = archive(base)
        compressed = gzip.compress(safe)
        self.assertEqual(reader(io.BytesIO(compressed), p), (b"ca", b"key"))
        # The malformed header is an additional member, after both valid targets.
        damaged = bytearray(archive(base + [("damaged", b"x", tarfile.REGTYPE)]))
        damaged[2048] ^= 1
        bad_crc = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
        extra_zeros = b"\0" * (32 * 1024 * 1024 + 512 - len(safe))
        # Legal gzip FCOMMENT grows only raw input; decoded tar stays valid.
        oversized_header = (compressed[:3] + bytes([compressed[3] | 16]) + compressed[4:10]
                            + b"c" * (32 * 1024 * 1024) + b"\0" + compressed[10:])
        defects = {
            "gzip concatenation": compressed + compressed,
            "compressed junk": compressed + b"junk",
            "zero compressed trailer": compressed + b"\0" * 512,
            "gzip crc": bad_crc,
            "truncated gzip": compressed[:-1],
            "hidden tar member": gzip.compress(safe + archive([("hidden", b"x", tarfile.REGTYPE)])),
            "nonzero tar trailer": gzip.compress(safe + b"x" * 512),
            "short tar trailer": gzip.compress(safe + b"\0"),
            "missing tar terminator": gzip.compress(safe[:2048]),
            "truncated tar body": gzip.compress(archive(base + [("truncated", b"x" * 512, tarfile.REGTYPE)])[:2570]),
            "tar checksum": gzip.compress(damaged),
            "decoded limit": gzip.compress(safe + extra_zeros),
            "raw limit": oversized_header,
            "member count": gzip.compress(archive(base + [(f"member-{n}", b"x", tarfile.REGTYPE) for n in range(127)])),
        }
        for name, raw in defects.items():
            with self.subTest(defect=name), self.assertRaises(self.c.SetupError) as caught:
                reader(io.BytesIO(raw), p)
            self.assertEqual(str(caught.exception), "archive_invalid")
        with self.assertRaises(self.c.SetupError):
            reader(io.BytesIO(compressed), self.p)  # Only defect: CA file pin.

    def nft_document(self):
        table = "aegis_wazuh_http_v1"
        def rule(expr):
            return {"rule": {"family": "inet", "table": table, "chain": "input", "handle": 4, "expr": expr}}
        def match(left, right):
            return {"match": {"op": "==", "left": left, "right": right}}
        payload = lambda proto, field: {"payload": {"protocol": proto, "field": field}}
        dest = [match(payload("ip", "daddr"), "10.23.45.10"), match(payload("tcp", "dport"), 9200)]
        return {"nftables": [{"metainfo": {"version": "synthetic"}},
                {"table": {"family": "inet", "name": table, "handle": 1}},
                {"chain": {"family": "inet", "table": table, "name": "input", "type": "filter", "hook": "input", "prio": -50, "policy": "accept", "handle": 2}},
                rule(dest + [match({"meta": {"key": "iifname"}}, "lo"), {"accept": None}]),
                rule(dest + [match(payload("ip", "saddr"), "10.23.45.20"), {"accept": None}]),
                rule(dest + [{"drop": None}])]}

    def test_firewall_verifies_full_semantics_and_ignores_handles(self):
        doc = self.nft_document()
        self.f.verify_table(doc, self.p)
        for mutate in [lambda d: d["nftables"][2]["chain"].update(prio=0),
                       lambda d: d["nftables"].pop(),
                       lambda d: d["nftables"].append(d["nftables"][-1]),
                       lambda d: d["nftables"][3]["rule"]["expr"].pop(0),
                       lambda d: d["nftables"][4]["rule"]["expr"][-1].update(drop=None)]:
            bad = copy.deepcopy(doc)
            mutate(bad)
            with self.subTest(mutate=mutate), self.assertRaises(self.c.SetupError):
                self.f.verify_table(bad, self.p)

    def test_observed_native_table_only_document_still_refuses(self):
        # CI40914859647 observed create-table block input install only this
        # container. Missing chain/rules is a real defect, not ignorable JSON.
        document = {"nftables": [{"table": {"family": "inet", "name": "aegis_wazuh_http_v1"}}]}
        with self.assertRaisesRegex(self.c.SetupError, "firewall_mismatch"):
            self.f.verify_table(document, self.p)

    def test_exclusive_firewall_batch_explicitly_adds_chain_and_all_rules(self):
        render = getattr(self.f, "firewall_create_text", lambda p: "create " + self.f.firewall_text(p))
        lines = render(self.p).splitlines()
        self.assertEqual(lines, [
            "create table inet aegis_wazuh_http_v1",
            "add chain inet aegis_wazuh_http_v1 input { type filter hook input priority -50; policy accept; }",
            'add rule inet aegis_wazuh_http_v1 input ip daddr 10.23.45.10 tcp dport 9200 iifname "lo" accept',
            "add rule inet aegis_wazuh_http_v1 input ip daddr 10.23.45.10 tcp dport 9200 ip saddr 10.23.45.20 accept",
            "add rule inet aegis_wazuh_http_v1 input ip daddr 10.23.45.10 tcp dport 9200 drop"])

    def test_rendered_firewall_and_boot_guards_preserve_fail_closed_order(self):
        text = self.f.firewall_text(self.p)
        self.assertIn("type filter hook input priority -50; policy accept;", text)
        self.assertIn('ip daddr 10.23.45.10 tcp dport 9200 iifname "lo" accept', text)
        self.assertIn("ip daddr 10.23.45.10 tcp dport 9200 ip saddr 10.23.45.20 accept", text)
        self.assertIn("ip daddr 10.23.45.10 tcp dport 9200 drop", text)
        self.assertNotIn("flush", text)
        unit = self.f.guard_unit()
        self.assertIn("Before=wazuh-indexer.service", unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        self.assertIn("guard-ensure --profile /etc/aegis-wazuh-https/profile.json", unit)
        self.assertNotIn("ExecStop", unit)
        dropin = self.f.indexer_dropin()
        self.assertIn("Requires=aegis-wazuh-http-guard.service", dropin)
        self.assertIn("After=aegis-wazuh-http-guard.service", dropin)
        self.assertIn("ExecStartPre=+/usr/bin/python3 -I -B /usr/local/lib/aegis-wazuh-https/Setup-Wazuh-HTTPS.py guard-verify --profile /etc/aegis-wazuh-https/profile.json", dropin)
        self.assertNotIn("User=", dropin)


class Certificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Components.setUpClass.__func__(cls)
        cls.openssl = shutil.which("openssl")
        if not cls.openssl and Path("C:/Program Files/Git/usr/bin/openssl.exe").is_file():
            cls.openssl = "C:/Program Files/Git/usr/bin/openssl.exe"

    def setUp(self):
        Components.setUp(self)
        if not self.openssl:
            if os.environ.get("AEGIS_REQUIRE_NATIVE") == "1":
                self.fail("OpenSSL required for native qualification")
            self.skipTest("OpenSSL unavailable for local component tests")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        def run(*args):
            return subprocess.run([self.openssl, *map(str, args)], cwd=self.root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60).stdout
        self.run_ssl = run
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Synthetic CA", "-days", "30", "-addext", "basicConstraints=critical,CA:TRUE")
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "old.key", "-out", "old.pem", "-subj", "/C=US/O=Synthetic/CN=indexer.example.test", "-days", "30")
        self.ca = (self.root / "ca.pem").read_bytes()
        self.key = (self.root / "ca.key").read_bytes()
        self.old = (self.root / "old.pem").read_bytes()
        self.raw.update(expected_ca_file_sha256=hashlib.sha256(self.ca).hexdigest(),
                        expected_ca_der_sha256=hashlib.sha256(run("x509", "-in", "ca.pem", "-outform", "DER")).hexdigest(),
                        expected_leaf_der_sha256=hashlib.sha256(run("x509", "-in", "old.pem", "-outform", "DER")).hexdigest())
        self.p = self.c.load_profile(json.dumps(self.raw).encode())

    def test_certificate_has_exact_sans_eku_subject_pkcs8_and_ca_bounded_validity(self):
        cert, key = self.cert.create_http_certificate(self.root, self.p, self.ca, self.key, self.old)
        self.assertTrue(key.startswith(b"-----BEGIN PRIVATE KEY-----"))
        (self.root / "new.pem").write_bytes(cert)
        (self.root / "new.key").write_bytes(key)
        decoded = __import__("ssl")._ssl._test_decode_cert(str(self.root / "new.pem"))
        self.assertEqual(decoded["subjectAltName"], (("IP Address", "127.0.0.1"), ("IP Address", "10.23.45.10")))
        ssl = __import__("ssl")
        self.assertLessEqual(ssl.cert_time_to_seconds(decoded["notAfter"]), ssl.cert_time_to_seconds(ssl._ssl._test_decode_cert(str(self.root / "ca.pem"))["notAfter"]))
        self.assertLessEqual(ssl.cert_time_to_seconds(decoded["notAfter"]) - ssl.cert_time_to_seconds(decoded["notBefore"]), 365 * 86400)
        self.assertEqual(self.run_ssl("x509", "-in", "new.pem", "-subject", "-noout"), self.run_ssl("x509", "-in", "old.pem", "-subject", "-noout"))
        self.assertIn(b"TLS Web Server Authentication", self.run_ssl("x509", "-in", "new.pem", "-ext", "extendedKeyUsage", "-noout"))
        self.assertIn(b"CA:FALSE", self.run_ssl("x509", "-in", "new.pem", "-ext", "basicConstraints", "-noout"))
        (self.root / "new.pub").write_bytes(self.run_ssl("pkey", "-in", "new.key", "-pubout"))
        self.assertIn(b"3072 bit", self.run_ssl("pkey", "-pubin", "-in", "new.pub", "-text", "-noout"))
        self.assertEqual(self.run_ssl("x509", "-in", "new.pem", "-pubkey", "-noout"), self.run_ssl("pkey", "-in", "new.key", "-pubout"))

    def test_certificate_validity_is_365_days_for_long_lived_ca(self):
        self.run_ssl("x509", "-in", "ca.pem", "-signkey", "ca.key", "-days", "500", "-out", "long-ca.pem")
        ca = (self.root / "long-ca.pem").read_bytes()
        self.raw.update(expected_ca_file_sha256=hashlib.sha256(ca).hexdigest(),
                        expected_ca_der_sha256=hashlib.sha256(self.run_ssl("x509", "-in", "long-ca.pem", "-outform", "DER")).hexdigest())
        p = self.c.load_profile(json.dumps(self.raw).encode())
        cert, _ = self.cert.create_http_certificate(self.root, p, ca, self.key, self.old)
        (self.root / "new.pem").write_bytes(cert)
        ssl = __import__("ssl")
        info = ssl._ssl._test_decode_cert(str(self.root / "new.pem"))
        self.assertEqual(ssl.cert_time_to_seconds(info["notAfter"]) - ssl.cert_time_to_seconds(info["notBefore"]), 365 * 86400)

    def test_certificate_refuses_ca_with_no_full_day_remaining(self):
        self.run_ssl("x509", "-in", "ca.pem", "-signkey", "ca.key", "-days", "0", "-out", "short-ca.pem")
        ca = (self.root / "short-ca.pem").read_bytes()
        self.raw.update(expected_ca_file_sha256=hashlib.sha256(ca).hexdigest(),
                        expected_ca_der_sha256=hashlib.sha256(self.run_ssl("x509", "-in", "short-ca.pem", "-outform", "DER")).hexdigest())
        p = self.c.load_profile(json.dumps(self.raw).encode())
        with self.assertRaises(self.c.SetupError) as caught:
            self.cert.create_http_certificate(self.root, p, ca, self.key, self.old)
        self.assertEqual(str(caught.exception), "certificate_invalid")

    def test_certificate_rejects_mismatched_ca_key_and_pins_without_leaking_input(self):
        for ca, key, old in [(self.ca, (self.root / "old.key").read_bytes(), self.old),
                             (self.old, self.key, self.old), (self.ca, self.key, self.ca)]:
            with self.subTest(ca_matches=ca == self.ca), self.assertRaises(self.c.SetupError) as caught:
                self.cert.create_http_certificate(self.root, self.p, ca, key, old)
            self.assertIn(str(caught.exception), {"certificate_invalid", "openssl_failed"})
            self.assertNotIn("PRIVATE", str(caught.exception))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["ca.key", "ca.pem", "old.key", "old.pem"])


if __name__ == "__main__":
    unittest.main()
