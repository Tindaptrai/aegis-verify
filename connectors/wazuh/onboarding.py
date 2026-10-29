"""Fixed, zero-hit Wazuh Indexer onboarding probe. No Django or collection writes."""
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPException, HTTPResponse, HTTPSConnection
import ipaddress
import json
import queue
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from cryptography import x509
from .live import _DeadlineSocket, LiveError


class ProbeError(Exception):
    """Only fixed codes; never attach source exceptions or response bodies."""


@dataclass(frozen=True)
class Target:
    origin: str
    addresses: tuple[str, ...]
    indices: tuple[str, ...]


def safe_address(value):
    try:
        address = ipaddress.ip_address(value)
        if (address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast
                or getattr(address, 'ipv4_mapped', None) is not None or '%' in value
                or (address.version == 4 and not (address.is_private or address.is_global))
                or (address.version == 6 and not address.is_global)):
            raise ValueError
        return str(address)
    except ValueError:
        raise ProbeError('policy_denied') from None


def origin(value):
    try:
        if type(value) is not str or len(value) > 2048 or any(c.isspace() or ord(c) < 32 for c in value):
            raise ValueError
        url = urlsplit(value)
        if (url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None
                or url.path or url.query or url.fragment or any(c in value for c in ('%', '\\', '?', '#'))):
            raise ValueError
        host, port = url.hostname, url.port or 443
        if not 1 <= port <= 65535 or not host.isascii() or host.endswith('.'):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                                      for part in host.split('.')):
                raise ValueError
        else:
            safe_address(host)
        canonical = f'https://[{host}]' if ':' in host else f'https://{host}'
        if url.port is not None:
            canonical += f':{port}'
        if value != canonical:
            raise ValueError
        return host, port
    except (ValueError, TypeError):
        raise ProbeError('invalid_request') from None


def validate_index(value):
    if type(value) is not str or not re.fullmatch(r'[a-z0-9][a-z0-9._*-]{0,127}', value) or '..' in value:
        raise ProbeError('invalid_request')


def validate_ca(value):
    try:
        if type(value) is not str or not 0 < len(value.encode('utf-8')) <= 65536:
            raise ValueError
        raw = value.encode('ascii')
        blocks = re.findall(rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----', raw)
        if not blocks or re.sub(rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----', b'', raw).strip():
            raise ValueError
        now = datetime.now(timezone.utc)
        for block in blocks:
            cert = x509.load_pem_x509_certificate(block)
            if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError
            if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
                raise ValueError
        return sha256(raw).hexdigest()
    except (ValueError, UnicodeError, x509.ExtensionNotFound):
        raise ProbeError('invalid_ca') from None


# A timed-out OS DNS call cannot be cancelled portably. Daemon slots remain held
# until that call ends, so repeated timeouts cannot create unbounded threads.
_dns_slots = threading.BoundedSemaphore(4)
_probe_slots = threading.BoundedSemaphore(4)


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise ProbeError('connection_unavailable')
    return value


def resolve(host, port, allowed, deadline):
    if not _dns_slots.acquire(blocking=False):
        raise ProbeError('rate_limited')
    output = queue.Queue(maxsize=1)
    def lookup():
        try:
            output.put(socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM))
        except Exception:
            output.put(None)
        finally:
            _dns_slots.release()
    threading.Thread(target=lookup, daemon=True, name='onboarding-dns').start()
    try:
        answers = output.get(timeout=remaining(deadline))
    except queue.Empty:
        raise ProbeError('connection_unavailable') from None
    remaining(deadline)
    if not answers:
        raise ProbeError('connection_unavailable')
    permitted = frozenset(safe_address(value) for value in allowed)
    for family, kind, protocol, _, address in answers:
        if (family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM
                or safe_address(address[0]) not in permitted or address[1] != port):
            raise ProbeError('policy_denied')
    return tuple(answers)


class _PinnedHTTPS(HTTPSConnection):
    def __init__(self, host, port, context, answers, deadline):
        super().__init__(host, port, context=context, timeout=remaining(deadline))
        self.answers, self.deadline = answers, deadline
        self.response_class = lambda sock, **kwargs: HTTPResponse(
            _DeadlineSocket(sock, deadline, 'connection_unavailable'), **kwargs)

    def connect(self):
        # Direct numeric sockaddr; HTTPSConnection never does another resolution.
        family, kind, protocol, _, address = self.answers[0]
        sock = socket.socket(family, kind, protocol)
        try:
            sock.settimeout(remaining(self.deadline))
            sock.connect(address)
            sock.settimeout(remaining(self.deadline))
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            remaining(self.deadline)
        except Exception:
            sock.close()
            raise

    def send(self, data):
        if self.sock is None:
            self.connect()
        self.sock.settimeout(remaining(self.deadline))
        super().send(data)
        remaining(self.deadline)


def _unique(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError
        output[key] = value
    return output


def check_response(status, headers, raw):
    if status == 401:
        raise ProbeError('authentication_failed')
    if status == 403:
        raise ProbeError('query_denied')
    try:
        if (status != 200 or len(raw) > 65536 or headers.get('content-encoding', 'identity') != 'identity'
                or headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json'):
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (type(value) is not dict or value.get('timed_out') is not False or 'error' in value
                or value.get('_shards', {}).get('failed') != 0 or value.get('hits', {}).get('hits') != []):
            raise ValueError
    except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
        raise ProbeError('query_failed') from None


def probe(*, endpoint, index, username, password, ca_pem, policy_provider):
    """Read policy immediately before DNS/TCP; never return or collect events."""
    host, port = origin(endpoint)
    validate_index(index)
    validate_ca(ca_pem)
    if not _probe_slots.acquire(blocking=False):
        raise ProbeError('rate_limited')
    connection = None
    try:
        deadline = time.monotonic() + 10
        target = policy_provider(endpoint, index)
        if not isinstance(target, Target) or target.origin != endpoint or index not in target.indices:
            raise ProbeError('policy_denied')
        answers = resolve(host, port, target.addresses, deadline)
        if policy_provider(endpoint, index) != target:
            raise ProbeError('policy_denied')
        remaining(deadline)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.hostname_checks_common_name = False
        context.load_verify_locations(cadata=ca_pem)
        connection = _PinnedHTTPS(host, port, context, answers, deadline)
        # Complete chain + SAN verification before constructing/sending Basic auth.
        connection.connect()
        if policy_provider(endpoint, index) != target:
            raise ProbeError('policy_denied')
        remaining(deadline)
        auth = base64.b64encode(f'{username}:{password}'.encode()).decode('ascii')
        body = b'{"size":0,"track_total_hits":false,"query":{"match_none":{}}}'
        connection.request('POST', f'/{index}/_search', body, headers={
            'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json',
            'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Connection': 'close'})
        response = connection.getresponse()
        headers = dict((key.lower(), value) for key, value in response.getheaders())
        # Never consume arbitrary error bodies or compressed streams.
        if response.status != 200 or headers.get('content-encoding', 'identity') != 'identity':
            check_response(response.status, headers, b'')
        length = headers.get('content-length')
        if length is not None and (not length.isdecimal() or int(length) > 65536):
            raise ProbeError('query_failed')
        raw = response.read(65537)
        remaining(deadline)
        check_response(response.status, headers, raw)
    except ssl.SSLError:
        raise ProbeError('tls_failed') from None
    except (OSError, HTTPException, LiveError):
        raise ProbeError('connection_unavailable') from None
    finally:
        if connection is not None:
            connection.close()
        _probe_slots.release()
