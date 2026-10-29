"""Synthetic certificates only; these tests make no lab compatibility claim."""
from datetime import datetime, timedelta, timezone
import socket
import ssl
import tempfile
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aegis_verify.connectors.wazuh import onboarding as probe


def certificate(*, ca=True, expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'synthetic-test-ca')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=2))
            .not_valid_after(now + timedelta(days=-1 if expired else 2))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class ProbeTests(unittest.TestCase):
    def test_shared_ipv4_and_non_global_ipv6_fail_closed_even_if_policy_listed(self):
        for address in ('100.64.1.2','fd12:3456:789a::1234','2001:db8::1234'):
            with self.subTest(address=address), self.assertRaises(probe.ProbeError):
                probe.safe_address(address)
        self.assertEqual(probe.safe_address('10.23.45.67'),'10.23.45.67')

    def test_policy_changed_during_dns_never_sends_credentials(self):
        target = probe.Target('https://indexer.example:9200', ('192.0.2.10',), ('wazuh-alerts-*',))
        provider = MagicMock(side_effect=[target, probe.ProbeError('policy_denied')])
        with patch.object(probe, 'resolve', return_value=((socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.10',9200)),)), \
             patch.object(probe, '_PinnedHTTPS') as connection, self.assertRaises(probe.ProbeError):
            probe.probe(endpoint=target.origin,index='wazuh-alerts-*',username='synthetic',password='synthetic',
                        ca_pem=certificate(), policy_provider=provider)
        connection.assert_not_called()

    def test_policy_revoked_during_tls_never_sends_credentials(self):
        target = probe.Target('https://indexer.example:9200',('192.0.2.10',),('wazuh-alerts-*',))
        provider = MagicMock(side_effect=[target,target,probe.ProbeError('policy_denied')])
        with patch.object(probe,'resolve',return_value=()), patch.object(probe,'_PinnedHTTPS') as connection, \
             self.assertRaises(probe.ProbeError):
            probe.probe(endpoint=target.origin,index='wazuh-alerts-*',username='synthetic',password='synthetic',
                        ca_pem=certificate(),policy_provider=provider)
        connection.return_value.request.assert_not_called()

    def test_transport_pins_sockaddr_and_original_tls_hostname(self):
        context = MagicMock()
        answers = ((socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.10',9200)),)
        transport = probe._PinnedHTTPS('indexer.example',9200,context,answers,time.monotonic()+1)
        with patch.object(socket,'socket') as sock, patch.object(socket,'getaddrinfo') as dns:
            transport.connect()
            sock.return_value.connect.assert_called_once_with(('192.0.2.10',9200))
            context.wrap_socket.assert_called_once_with(sock.return_value,server_hostname='indexer.example')
            dns.assert_not_called()

    def test_probe_preserves_tls_verification_and_zero_hit_route(self):
        target = probe.Target('https://indexer.example:9200',('192.0.2.10',),('wazuh-alerts-*',))
        with patch.object(probe,'resolve',return_value=()), patch.object(probe,'_PinnedHTTPS') as conn:
            response = conn.return_value.getresponse.return_value
            response.status = 200
            response.getheaders.return_value = [('Content-Type','application/json')]
            response.read.return_value = b'{"timed_out":false,"_shards":{"failed":0},"hits":{"hits":[]}}'
            probe.probe(endpoint=target.origin,index='wazuh-alerts-*',username='synthetic',password='synthetic',
                        ca_pem=certificate(),policy_provider=lambda *_:target)
            context = conn.call_args.args[2]
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, probe.ssl.CERT_REQUIRED)
            args = conn.return_value.request.call_args.args
            self.assertEqual(args[:2],('POST','/wazuh-alerts-*/_search'))
            self.assertEqual(probe.json.loads(args[2])['size'],0)
            self.assertEqual(response.read.call_args.args,(65537,))

    def test_origin_is_closed(self):
        for value in ('http://example.test', 'https://user:pass@example.test', 'https://example.test/path',
                      'https://example.test/?q=1', 'https://example.test/#x', 'https://example.test%2f',
                      'https://127.0.0.1', 'https://[::1]', 'https://169.254.169.254', 'https://example.test\\evil'):
            with self.subTest(value=value), self.assertRaises(probe.ProbeError):
                probe.origin(value)
        self.assertEqual(probe.origin('https://indexer.example:9200'), ('indexer.example', 9200))

    def test_ca_must_be_only_current_ca_certificates(self):
        good = certificate()
        self.assertEqual(len(probe.validate_ca(good)), 64)
        for value in ('no pem', good + 'extra', good + '\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----',
                      certificate(expired=True), certificate(ca=False)):
            with self.subTest(value=value[:20]), self.assertRaises(probe.ProbeError) as ctx:
                probe.validate_ca(value)
            self.assertEqual(str(ctx.exception), 'invalid_ca')

    def test_resolution_rejects_one_unapproved_result(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.10', 9200)),
                   (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.11', 9200))]
        with patch.object(socket, 'getaddrinfo', return_value=answers), self.assertRaises(probe.ProbeError) as ctx:
            probe.resolve('indexer.example', 9200, ('192.0.2.10',), time.monotonic() + 1)
        self.assertEqual(str(ctx.exception), 'policy_denied')

    def test_slow_resolver_is_bounded(self):
        def slow(*args):
            time.sleep(.15)
            return []
        start = time.monotonic()
        with patch.object(socket, 'getaddrinfo', side_effect=slow), self.assertRaises(probe.ProbeError):
            probe.resolve('indexer.example', 9200, ('192.0.2.10',), start + .02)
        self.assertLess(time.monotonic() - start, .12)

    def test_response_schema_and_auth_errors_do_not_expose_body(self):
        good = b'{"timed_out":false,"_shards":{"failed":0},"hits":{"hits":[]}}'
        probe.check_response(200, {'content-type': 'application/json'}, good)
        for status, headers, body, code in (
            (401, {}, b'secret', 'authentication_failed'), (403, {}, b'secret', 'query_denied'),
            (302, {}, b'secret', 'query_failed'), (200, {'content-encoding':'gzip'}, good, 'query_failed'),
            (200, {}, b'x'*65537, 'query_failed'), (200, {}, b'{}', 'query_failed'),
            (200, {}, good.replace(b'[]', b'[{"secret":1}]'), 'query_failed')):
            with self.assertRaises(probe.ProbeError) as ctx:
                probe.check_response(status, headers, body)
            self.assertEqual(str(ctx.exception), code)


class SyntheticTlsTests(unittest.TestCase):
    """Real local TLS, generated ephemeral CA/leaf; no production policy bypass."""
    def handshake(self, hostname, *, trust=True, expired=False):
        now = datetime.now(timezone.utc)
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic-root')])
        ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2))
              .not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
              .sign(key,hashes.SHA256()))
        leaf_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic-leaf')])
        leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(name).public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2))
                .not_valid_after(now+timedelta(days=-1 if expired else 1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('indexer.example')]),False)
                .sign(key,hashes.SHA256()))
        observed = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'leaf.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
            (root/'key.pem').write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.load_cert_chain(root/'leaf.pem',root/'key.pem')
            server.set_servername_callback(lambda sock,name,context:observed.append(name))
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0))
                listener.listen(1)
                listener.settimeout(2)
                port = listener.getsockname()[1]
                def accept():
                    try:
                        accepted,_ = listener.accept()
                        with accepted:
                            accepted.settimeout(2)
                            with server.wrap_socket(accepted,server_side=True):
                                pass
                    except (ssl.SSLError,OSError):
                        pass
                thread = threading.Thread(target=accept,daemon=True)
                thread.start()
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if trust:
                    context.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM).decode())
                transport = probe._PinnedHTTPS(hostname,port,context,
                    ((socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',port)),),time.monotonic()+2)
                try:
                    transport.connect()
                finally:
                    transport.close()
                    thread.join(timeout=2)
        return observed

    def test_trusted_san_and_sni(self):
        self.assertEqual(self.handshake('indexer.example'),['indexer.example'])

    def test_wrong_san_chain_and_expired_leaf_are_refused(self):
        for hostname, trust, expired in [('wrong.example',True,False),('indexer.example',False,False),
                                        ('indexer.example',True,True)]:
            with self.subTest(hostname=hostname,trust=trust,expired=expired), self.assertRaises(ssl.SSLError):
                self.handshake(hostname,trust=trust,expired=expired)

    def test_drip_feed_cannot_extend_absolute_response_deadline(self):
        from aegis_verify.connectors.wazuh.live import _DeadlineSocket, LiveError
        reader, writer = socket.socketpair()
        stop = threading.Event()
        def drip():
            while not stop.wait(.005):
                try:
                    writer.sendall(b'x')
                except OSError:
                    break
        thread = threading.Thread(target=drip,daemon=True)
        start = time.monotonic()
        thread.start()
        try:
            with _DeadlineSocket(reader,start+.04,'connection_unavailable').makefile('rb') as stream:
                with self.assertRaises((LiveError,TimeoutError)):
                    stream.read(100)
            self.assertLess(time.monotonic()-start,.3)
        finally:
            stop.set()
            reader.close()
            writer.close()
            thread.join(timeout=1)
