"""Local certificate issuance with a pre-existing CA; keys never leave work RAM/files.

OpenSSL is invoked with argv, no shell, bounded execution and discarded diagnostics.
The caller owns host file provenance and supplies a trusted, root-only work directory.
"""
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time

from .contracts import Profile, SetupError


def _openssl() -> str:
    found = shutil.which("openssl")
    # Development-only Windows distribution; installed Linux uses its trusted PATH.
    candidate = Path("C:/Program Files/Git/usr/bin/openssl.exe")
    if not found and os.name == "nt" and candidate.is_file():
        found = str(candidate)
    if not found:
        raise SetupError("openssl_failed")
    return found


def create_http_certificate(work: Path, p: Profile, ca_pem: bytes, ca_key: bytes,
                            old_leaf: bytes) -> tuple[bytes, bytes]:
    """Return only a fully verified leaf/key; retain no temporary signing material."""
    if any(not isinstance(body, bytes) or not body or len(body) > 1024 * 1024 for body in (ca_pem, ca_key, old_leaf)):
        raise SetupError("certificate_invalid")
    if hashlib.sha256(ca_pem).hexdigest() != p.expected_ca_file_sha256:
        raise SetupError("certificate_invalid")
    try:
        if not work.is_dir() or any(part.is_symlink() for part in (work, *work.parents)):
            raise SetupError("certificate_invalid")
        openssl = _openssl()
        with tempfile.TemporaryDirectory(prefix="issue-", dir=work) as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)

            def put(name, body):
                fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(body)

            def run(*args):
                try:
                    result = subprocess.run([openssl, *args], cwd=root, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                            timeout=60, check=False)
                except (OSError, subprocess.TimeoutExpired):
                    raise SetupError("openssl_failed") from None
                if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
                    raise SetupError("openssl_failed")
                return result.stdout

            put("ca.pem", ca_pem)
            put("ca-key.pem", ca_key)
            put("old.pem", old_leaf)
            for name, pin in (("ca.pem", p.expected_ca_der_sha256), ("old.pem", p.expected_leaf_der_sha256)):
                if hashlib.sha256(run("x509", "-in", name, "-outform", "DER")).hexdigest() != pin:
                    raise SetupError("certificate_invalid")
            if run("x509", "-in", "ca.pem", "-pubkey", "-noout") != run("pkey", "-in", "ca-key.pem", "-passin", "pass:", "-pubout"):
                raise SetupError("certificate_invalid")
            constraints = run("x509", "-in", "ca.pem", "-ext", "basicConstraints", "-noout").decode("ascii")
            if "CA:TRUE" not in constraints:
                raise SetupError("certificate_invalid")
            ca_info = ssl._ssl._test_decode_cert(str(root / "ca.pem"))
            now = time.time()
            if ssl.cert_time_to_seconds(ca_info["notBefore"]) > now:
                raise SetupError("certificate_invalid")
            ca_end = ssl.cert_time_to_seconds(ca_info["notAfter"])
            days = min(365, int((ca_end - now) // 86400))
            if days < 1:
                raise SetupError("certificate_invalid")
            run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", "http-key.pem")
            os.chmod(root / "http-key.pem", 0o600)
            # Converting the old certificate to a CSR preserves its full subject.
            run("x509", "-x509toreq", "-in", "old.pem", "-signkey", "http-key.pem", "-out", "http.csr")
            put("extensions.cnf", ("[http]\nbasicConstraints=critical,CA:FALSE\n"
                                   "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                   "extendedKeyUsage=serverAuth\n"
                                   f"subjectAltName=IP:127.0.0.1,IP:{p.indexer_ip}\n").encode("ascii"))
            run("x509", "-req", "-in", "http.csr", "-CA", "ca.pem", "-CAkey", "ca-key.pem",
                "-passin", "pass:", "-set_serial", "0x" + secrets.token_hex(19), "-days", str(days),
                "-sha256", "-extfile", "extensions.cnf", "-extensions", "http", "-out", "http.pem")
            run("verify", "-CAfile", "ca.pem", "-purpose", "sslserver", "-verify_ip", p.indexer_ip, "http.pem")
            run("verify", "-CAfile", "ca.pem", "-purpose", "sslserver", "-verify_ip", "127.0.0.1", "http.pem")
            info = ssl._ssl._test_decode_cert(str(root / "http.pem"))
            before = ssl.cert_time_to_seconds(info["notBefore"])
            after = ssl.cert_time_to_seconds(info["notAfter"])
            if info.get("subjectAltName") != (("IP Address", "127.0.0.1"), ("IP Address", p.indexer_ip)):
                raise SetupError("certificate_invalid")
            if not (now - 10 <= before <= time.time() and before < after <= ca_end and after - before <= 365 * 86400):
                raise SetupError("certificate_invalid")
            if run("x509", "-in", "old.pem", "-subject", "-nameopt", "RFC2253", "-noout") != run("x509", "-in", "http.pem", "-subject", "-nameopt", "RFC2253", "-noout"):
                raise SetupError("certificate_invalid")
            if run("x509", "-in", "http.pem", "-pubkey", "-noout") != run("pkey", "-in", "http-key.pem", "-pubout"):
                raise SetupError("certificate_invalid")
            eku = run("x509", "-in", "http.pem", "-ext", "extendedKeyUsage", "-noout").decode("ascii").splitlines()
            basic = run("x509", "-in", "http.pem", "-ext", "basicConstraints", "-noout").decode("ascii").splitlines()
            if len(eku) != 2 or eku[1].strip() != "TLS Web Server Authentication" or len(basic) != 2 or basic[1].strip() != "CA:FALSE":
                raise SetupError("certificate_invalid")
            cert = (root / "http.pem").read_bytes()
            key = (root / "http-key.pem").read_bytes()
            if not key.startswith(b"-----BEGIN PRIVATE KEY-----"):
                raise SetupError("certificate_invalid")
            return cert, key
    except (OSError, ValueError, UnicodeError, ssl.SSLError):
        raise SetupError("certificate_invalid") from None
