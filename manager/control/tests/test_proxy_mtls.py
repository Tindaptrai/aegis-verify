"""Synthetic, local nginx mTLS deployment-boundary test."""

import http.client
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.test import LiveServerTestCase, override_settings
from django.contrib.auth import get_user_model
from django.utils import timezone

from control.models import Device, DispatchLock
from accounts.models import AccountMutationLock
from devices.issuer import initialize_issuer
from devices.services import create_pairing_code
from devices.tests.helpers import csr


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _certificate(subject, key, issuer, issuer_key, *, ca=False, usage=None):
    now = timezone.now()
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5))
               .not_valid_after(now + timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                   key_encipherment=not ca, data_encipherment=False, key_agreement=False,
                   key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True))
    if subject == "localhost" and not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
    if usage:
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _write_pair(directory, stem, key, cert):
    cert_path = directory / f"{stem}.pem"
    key_path = directory / f"{stem}-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    return cert_path, key_path


@unittest.skipUnless(shutil.which("nginx"), "nginx executable is required for real mTLS integration")
@override_settings(ALLOWED_HOSTS=["localhost", "testserver"])
class NginxMutualTlsTests(LiveServerTestCase):
    """Run the shipped proxy policy with synthetic keys and a real ORM API."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.temp = tempfile.TemporaryDirectory(prefix="aegis-nginx-mtls-")
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        root = root.resolve()
        cls.issuer_settings = override_settings(PRIVATE_ROOT=root, ENROLLMENT_CA_KEY=str(root / "enrollment-key.pem"),
                                                ENROLLMENT_CA_CERT=str(root / "enrollment.pem"))
        cls.issuer_settings.enable()
        cls.addClassCleanup(cls.issuer_settings.disable)
        initialize_issuer()
        cls.ca_key = _key()
        cls.ca = _certificate("synthetic-agent-ca", cls.ca_key,
                              "synthetic-agent-ca", cls.ca_key, ca=True)
        (root / "agent-ca.pem").write_bytes(cls.ca.public_bytes(serialization.Encoding.PEM) + (root / "enrollment.pem").read_bytes())
        server_key = _key()
        server = _certificate("localhost", server_key, "synthetic-agent-ca", cls.ca_key,
                              usage=ExtendedKeyUsageOID.SERVER_AUTH)
        server_cert, server_key_path = _write_pair(root, "server", server_key, server)
        cls.client_key = _key()
        cls.client_cert = _certificate("synthetic-enrolled", cls.client_key,
                                       "synthetic-agent-ca", cls.ca_key,
                                       usage=ExtendedKeyUsageOID.CLIENT_AUTH)
        cls.client_path, cls.client_key_path = _write_pair(root, "client", cls.client_key, cls.client_cert)
        other_key = _key()
        other = _certificate("synthetic-unenrolled", other_key,
                             "synthetic-agent-ca", cls.ca_key,
                             usage=ExtendedKeyUsageOID.CLIENT_AUTH)
        cls.other_path, cls.other_key_path = _write_pair(root, "unenrolled", other_key, other)
        foreign_ca_key = _key()
        foreign_ca = _certificate("synthetic-foreign-ca", foreign_ca_key,
                                  "synthetic-foreign-ca", foreign_ca_key, ca=True)
        foreign_key = _key()
        foreign = _certificate("synthetic-foreign", foreign_key,
                               "synthetic-foreign-ca", foreign_ca_key,
                               usage=ExtendedKeyUsageOID.CLIENT_AUTH)
        cls.foreign_path, cls.foreign_key_path = _write_pair(root, "foreign", foreign_key, foreign)

        with socket.create_server(("localhost", 0)) as reserved:
            cls.port = reserved.getsockname()[1]
        template = (Path(__file__).resolve().parents[3] / "deploy/manager/nginx.conf.example").read_text()
        # Keep the shipped server and location directives intact; substitute only
        # ephemeral listener, upstream, certificate and static-directory values.
        replacements = {
            "listen 443 ssl;": f"listen localhost:{cls.port} ssl;",
            "REPLACE_MANAGER_HOSTNAME": "localhost",
            "/etc/aegis-manager/tls/manager-chain.pem": server_cert.as_posix(),
            "/etc/aegis-manager/tls/manager-key.pem": server_key_path.as_posix(),
            "/etc/aegis-manager/tls/agent-ca.pem": (root / "agent-ca.pem").as_posix(),
            "http://localhost:8001": cls.live_server_url,
            "/srv/aegis-manager-static/": (root / "static").as_posix() + "/",
        }
        for old, new in replacements.items():
            if old not in template:
                raise AssertionError(f"nginx template changed: missing {old}")
            template = template.replace(old, new)
        (root / "static").mkdir()
        (root / "logs").mkdir()
        config = root / "nginx.conf"
        config.write_text(f"pid {root.as_posix()}/nginx.pid;\n"
                          f"error_log {root.as_posix()}/error.log;\n"
                          "events {}\nhttp {\naccess_log off;\n" + template + "\n}\n")
        command = [shutil.which("nginx"), "-p", str(root) + "/", "-c", str(config), "-g", "daemon off;"]
        check = subprocess.run(command[:-2] + ["-t"], capture_output=True, text=True)
        if check.returncode:
            raise AssertionError(f"nginx configuration failed: {check.stderr}")
        cls.nginx_log = (root / "nginx-output.log").open("w+")
        cls.addClassCleanup(cls.nginx_log.close)
        cls.nginx = subprocess.Popen(command, stdout=cls.nginx_log, stderr=subprocess.STDOUT)
        cls.addClassCleanup(cls._stop_nginx)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.nginx.poll() is not None:
                raise AssertionError("nginx exited before serving HTTPS")
            try:
                cls._request()
                break
            except (ConnectionRefusedError, TimeoutError, OSError):
                time.sleep(0.05)
        else:
            raise AssertionError("nginx did not begin serving HTTPS")

    @classmethod
    def _stop_nginx(cls):
        if cls.nginx.poll() is None:
            cls.nginx.terminate()
            try:
                cls.nginx.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.nginx.kill()
                cls.nginx.wait(timeout=5)

    @classmethod
    def _request(cls, cert=None, key=None, headers=None, *, path="/agent/v1/poll", body=None, return_body=False):
        context = ssl.create_default_context(cafile=str(Path(cls.temp.name) / "agent-ca.pem"))
        if cert:
            context.load_cert_chain(str(cert), str(key))
        connection = http.client.HTTPSConnection("localhost", cls.port, context=context, timeout=2)
        try:
            connection.request("POST", path, json.dumps({"protocol": "0.1.0"} if body is None else body),
                               {"Content-Type": "application/json"} | (headers or {}))
            response = connection.getresponse()
            payload = response.read()
            return (response.status, payload) if return_body else response.status
        finally:
            connection.close()

    def test_enrolled_certificate_reaches_poll(self):
        DispatchLock.objects.get_or_create(pk=1)
        Device.objects.create(environment_id="synthetic", wazuh_agent_id="synthetic",
                              certificate_sha256=self.client_cert.fingerprint(hashes.SHA256()).hex())
        self.assertEqual(self._request(self.client_path, self.client_key_path), 204)

    def test_missing_certificate_cannot_spoof_proxy_identity(self):
        spoof = {"X-Aegis-Client-Verify": "SUCCESS", "X-Aegis-Client-Cert":
                 quote(self.client_cert.public_bytes(serialization.Encoding.PEM).decode(), safe="")}
        self.assertEqual(self._request(headers=spoof), 403)

    def test_valid_ca_but_unenrolled_certificate_is_denied(self):
        self.assertEqual(self._request(self.other_path, self.other_key_path), 403)

    def test_revoked_database_device_is_denied(self):
        Device.objects.create(environment_id="synthetic", wazuh_agent_id="synthetic",
                              certificate_sha256=self.client_cert.fingerprint(hashes.SHA256()).hex(),
                              revoked=True)
        self.assertEqual(self._request(self.client_path, self.client_key_path), 403)

    def test_wrong_ca_client_certificate_is_rejected(self):
        try:
            status = self._request(self.foreign_path, self.foreign_key_path)
        except (ssl.SSLError, ConnectionResetError, http.client.RemoteDisconnected):
            return  # Some nginx/TLS versions close the connection before HTTP.
        self.assertGreaterEqual(status, 400)

    def test_server_certificate_requires_matching_hostname(self):
        context = ssl.create_default_context(cafile=str(Path(self.temp.name) / "agent-ca.pem"))
        with socket.create_connection(("localhost", self.port), timeout=2) as raw:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(raw, server_hostname="wrong.example")

    def _enrollment_body(self):
        AccountMutationLock.objects.get_or_create(pk=1)
        owner = get_user_model().objects.create_superuser("synthetic-pairing-owner")
        mint = create_pairing_code(actor=owner, environment_id="synthetic")
        key, pem = csr()
        return key, {"protocol": "2.0", "pairing_code": mint["code"], "csr_pem": pem,
                     "hostname": "synthetic-host", "os": "linux", "architecture": "x64", "agent_version": "0.1.0"}

    def test_bootstrap_without_certificate_and_paired_heartbeat_preserve_v1_exclusion(self):
        key, body = self._enrollment_body()
        status, payload = self._request(path="/agent/v2/enroll", body=body, return_body=True)
        self.assertEqual(status, 201)
        result = json.loads(payload)
        root = Path(self.temp.name)
        certificate = x509.load_pem_x509_certificate(result["certificate_pem"].encode())
        cert_path, key_path = _write_pair(root, "new-paired", key, certificate)
        heartbeat = {"protocol": "2.0", "device_id": result["device_id"], "generation": 1}
        self.assertEqual(self._request(cert_path, key_path, path="/agent/v2/heartbeat", body=heartbeat), 200)
        self.assertEqual(self._request(cert_path, key_path), 403)
        device = Device.objects.get(pk=result["device_id"])
        self.assertIsNotNone(device.last_heartbeat_at)

    def test_both_heartbeats_replace_forged_peer_header(self):
        now = timezone.now()
        device = Device.objects.create(environment_id="synthetic", connection_kind="paired_presence",
            certificate_sha256=self.client_cert.fingerprint(hashes.SHA256()).hex(),
            certificate_not_before=now - timedelta(hours=1), certificate_expires_at=now + timedelta(hours=1))
        for network in (False, True):
            body = {"protocol": "2.1" if network else "2.0", "device_id": str(device.pk), "generation": 1}
            if network:
                body["network"] = {"collection_status": "ok", "reported_ips": ["192.0.2.9"],
                                   "truncated": False, "agent_version": "0.2.0"}
            path = "/agent/v2/network-heartbeat" if network else "/agent/v2/heartbeat"
            with self.subTest(path=path):
                self.assertEqual(self._request(self.client_path, self.client_key_path,
                    headers={"X-Aegis-Peer-IP": "192.0.2.99, 192.0.2.100", "X-Forwarded-For": "192.0.2.99",
                             "Forwarded": "for=192.0.2.99"}, path=path, body=body), 200)
                device.refresh_from_db()
                self.assertIn(device.observed_ip, ("127.0.0.1", "::1"))
                self.assertIsNotNone(device.observed_ip_received_at)
                self.assertEqual(device.reported_ips, ["192.0.2.9"] if network else None)

    def test_network_heartbeat_requires_mtls_and_enrolled_identity(self):
        spoof = {"X-Aegis-Client-Verify": "SUCCESS", "X-Aegis-Client-Cert":
                 quote(self.client_cert.public_bytes(serialization.Encoding.PEM).decode(), safe=""),
                 "X-Aegis-Peer-IP": "192.0.2.9"}
        body = {"protocol": "2.1", "device_id": "00000000-0000-0000-0000-000000000001", "generation": 1,
                "network": {"collection_status": "unavailable", "reported_ips": None,
                            "truncated": False, "agent_version": "0.2.0"}}
        self.assertEqual(self._request(headers=spoof, path="/agent/v2/network-heartbeat", body=body), 403)
        self.assertEqual(self._request(self.other_path, self.other_key_path,
                                      path="/agent/v2/network-heartbeat", body=body), 403)
        self.assertEqual(self._request(self.client_path, self.client_key_path, path="/agent/v2/network-heartbeat",
                                      body={"padding": "x" * 16385}), 413)

    def test_bootstrap_strips_spoofed_identity_and_cannot_write_presence(self):
        _, body = self._enrollment_body()
        spoof = {"X-Aegis-Client-Verify": "SUCCESS", "X-Aegis-Client-Cert":
                 quote(self.client_cert.public_bytes(serialization.Encoding.PEM).decode(), safe="")}
        status, _ = self._request(headers=spoof, path="/agent/v2/enroll", body=body, return_body=True)
        self.assertEqual(status, 201)
        device = Device.objects.get()
        self.assertIsNone(device.last_heartbeat_at)
        heartbeat = {"protocol": "2.0", "device_id": str(device.pk), "generation": 1}
        self.assertEqual(self._request(headers=spoof, path="/agent/v2/heartbeat", body=heartbeat), 403)
        self.assertEqual(self._request(self.client_path, self.client_key_path,
                                      path="/agent/v2/heartbeat", body=heartbeat), 403)

    def test_heartbeat_rejects_wrong_trust_chain(self):
        try:
            status = self._request(self.foreign_path, self.foreign_key_path, path="/agent/v2/heartbeat", body={})
        except (ssl.SSLError, ConnectionResetError, http.client.RemoteDisconnected):
            return
        self.assertGreaterEqual(status, 400)

    def test_z_bootstrap_enforces_request_body_and_rate_limits(self):
        self.assertEqual(self._request(path="/agent/v2/enroll", body={"padding": "x" * 16385}), 413)
        statuses = [self._request(path="/agent/v2/enroll", body={}) for _ in range(8)]
        self.assertIn(429, statuses)
