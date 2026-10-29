"""Synthetic component tests; no services, host firewall or lab files are used."""
import copy
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
        for extra in [("link", b"", tarfile.SYMTYPE), ("link", b"", tarfile.LNKTYPE),
                      ("../outside", b"", tarfile.REGTYPE), ("/outside", b"", tarfile.REGTYPE),
                      ("certs/root-ca.pem", b"ca", tarfile.REGTYPE),
                      ("oversized", b"x" * (1024 * 1024 + 1), tarfile.REGTYPE)]:
            with self.subTest(extra=extra[0]), self.assertRaises(self.c.SetupError):
                self.c.archive_ca_members(archive(base + [extra]), self.p)
        with self.assertRaises(self.c.SetupError):
            self.c.archive_ca_members(b"x" * (32 * 1024 * 1024 + 1), self.p)

    def test_archive_rejects_hidden_concatenated_duplicates_and_compression_bombs(self):
        import gzip
        ca = b"synthetic ca"
        p = self.c.load_profile(json.dumps(dict(self.raw, expected_ca_file_sha256=hashlib.sha256(ca).hexdigest())).encode())
        safe = archive([("certs/root-ca.pem", ca, tarfile.REGTYPE), ("certs/root-ca.key", b"key", tarfile.REGTYPE)])
        self.assertEqual(self.c.archive_ca_members(gzip.compress(safe), p), (ca, b"key"))
        for bad in [safe + safe, gzip.compress(b"x" * (32 * 1024 * 1024 + 1)),
                    archive([(f"member-{n}", b"x", tarfile.REGTYPE) for n in range(129)])]:
            with self.subTest(size=len(bad)), self.assertRaises(self.c.SetupError):
                self.c.archive_ca_members(bad, p)

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
        self.assertIn("guard-ensure --profile /etc/wazuh-indexer/aegis-http/profile.json", unit)
        self.assertNotIn("ExecStop", unit)
        dropin = self.f.indexer_dropin()
        self.assertIn("Requires=aegis-wazuh-http-guard.service", dropin)
        self.assertIn("After=aegis-wazuh-http-guard.service", dropin)
        self.assertIn("ExecStartPre=/usr/bin/python3 /usr/local/lib/aegis-wazuh-https/Setup-Wazuh-HTTPS.py guard-verify --profile /etc/wazuh-indexer/aegis-http/profile.json", dropin)


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
