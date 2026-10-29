"""Closed deployment input contracts; no host mutation or source-value diagnostics."""
from dataclasses import asdict, dataclass
import hashlib
import io
import ipaddress
import json
from pathlib import PurePosixPath
import re
import tarfile
from typing import BinaryIO
import zlib


class SetupError(Exception):
    """Only fixed vocabulary may cross the public error boundary."""

    def __init__(self, code: str):
        safe = {"profile_invalid", "config_unsupported", "archive_invalid",
                "certificate_invalid", "openssl_failed", "firewall_mismatch",
                "host_unsupported", "path_untrusted", "listeners_unsupported",
                "state_changed", "operation_locked", "intent_exists",
                "recovery_required", "verification_failed", "manifest_invalid",
                "installed_only", "root_required", "command_failed", "no_intent",
                "vendor_drift", "filesystem_unsupported"}
        self.code = code if code in safe else "setup_failed"
        super().__init__(self.code)


@dataclass(frozen=True)
class Profile:
    schema_version: int
    hostname: str
    indexer_ip: str
    manager_ip: str
    config_path: str
    ca_path: str
    leaf_path: str
    ca_archive: str
    ca_member: str
    key_member: str
    expected_ca_file_sha256: str
    expected_ca_der_sha256: str
    expected_leaf_der_sha256: str

    def as_dict(self) -> dict:
        return asdict(self)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _path(value: str, *, absolute: bool) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", value):
        return False
    parts = value.split("/")
    if absolute:
        return value.startswith("/") and all(p not in {"", ".", ".."} for p in parts[1:])
    return not value.startswith("/") and all(p not in {"", ".", ".."} for p in parts)


def load_profile(raw: bytes) -> Profile:
    try:
        if not isinstance(raw, bytes) or len(raw) > 16384:
            raise ValueError
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(data, dict) or set(data) != set(Profile.__dataclass_fields__):
            raise ValueError
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ValueError
        if any(type(v) is not str or not v or len(v) > 1024 for k, v in data.items() if k != "schema_version"):
            raise ValueError
        hostname = data["hostname"]
        if len(hostname) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", s) for s in hostname.split(".")):
            raise ValueError
        for key in ("indexer_ip", "manager_ip"):
            ip = ipaddress.IPv4Address(data[key])
            # ipaddress.is_private also includes documentation/reserved networks.
            rfc1918 = any(ip in ipaddress.IPv4Network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
            if str(ip) != data[key] or not (rfc1918 or ip.is_global) or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved:
                raise ValueError
        if data["indexer_ip"] == data["manager_ip"]:
            raise ValueError
        for key in ("config_path", "ca_path", "leaf_path", "ca_archive"):
            if not _path(data[key], absolute=True):
                raise ValueError
        for key in ("config_path", "ca_path", "leaf_path"):
            if not data[key].startswith("/etc/wazuh-indexer/") or data[key].startswith("/etc/wazuh-indexer/aegis-http/"):
                raise ValueError
        paths = [data[k] for k in ("config_path", "ca_path", "leaf_path", "ca_archive")]
        if len(set(paths)) != len(paths):
            raise ValueError
        if any(PurePosixPath(data["ca_archive"]).is_relative_to(PurePosixPath(root)) for root in ("/usr/local/lib/aegis-wazuh-https", "/etc/wazuh-indexer/aegis-http")):
            raise ValueError
        for key in ("ca_member", "key_member"):
            if not _path(data[key], absolute=False):
                raise ValueError
        if data["ca_member"] == data["key_member"]:
            raise ValueError
        for key in ("expected_ca_file_sha256", "expected_ca_der_sha256", "expected_leaf_der_sha256"):
            if not re.fullmatch("[0-9a-f]{64}", data[key]):
                raise ValueError
        return Profile(**data)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise SetupError("profile_invalid") from None


def _yaml_value(value: str):
    """Read only single-line scalars or JSON-compatible flat scalar lists."""
    value = value.strip()
    if value.startswith(('"', '[')):
        parsed, end = json.JSONDecoder().raw_decode(value)
        trailing = value[end:].strip()
        if trailing and not trailing.startswith("#"):
            raise ValueError
        if not isinstance(parsed, (str, list)) or isinstance(parsed, list) and any(type(v) not in (str, int, bool) for v in parsed):
            raise ValueError
        return parsed
    if value.startswith("'"):
        match = re.fullmatch(r"'((?:[^']|'')*)'(?:[ ]+#.*)?", value)
        if not match:
            raise ValueError
        return match[1].replace("''", "'")
    match = re.fullmatch(r"([A-Za-z0-9_./:@+=-]+)(?:[ ]+#.*)?", value)
    if not match:
        raise ValueError
    return match[1]


def patch_http_config(raw: bytes, p: Profile) -> bytes:
    """Patch a deliberately small flat YAML subset without reserializing it.

    Unknown flat scalars and simple block lists retain their exact bytes.
    YAML aliases, mappings, tags, folded values and quoted keys are unsupported.
    """
    try:
        if len(raw) > 1024 * 1024 or b"\x00" in raw:
            raise ValueError
        text = raw.decode("utf-8")
        if any(ord(c) < 32 and c not in "\r\n" for c in text):
            raise ValueError
        newline = "\r\n" if "\r\n" in text else "\n"
        if "\r" in text.replace("\r\n", "") or (newline == "\r\n" and "\n" in text.replace("\r\n", "")):
            raise ValueError
        targets = {
            "http.bind_host": f'["127.0.0.1", "{p.indexer_ip}"]',
            "http.port": "9200",
            "http.publish_host": '"127.0.0.1"',
            "plugins.security.ssl.http.pemcert_filepath": '"/etc/wazuh-indexer/aegis-http/tls/indexer-http.pem"',
            "plugins.security.ssl.http.pemkey_filepath": '"/etc/wazuh-indexer/aegis-http/tls/indexer-http-key.pem"',
        }
        seen = set()
        output = []
        list_key = None
        list_count = 0
        for line in text.splitlines(keepends=True):
            body = line.removesuffix(newline)
            if not body.strip() or body.lstrip().startswith("#"):
                output.append(line)
                continue
            if body.startswith(" "):
                entry = re.fullmatch(r" +-[ ]+(.+)", body)
                if not list_key or not entry or isinstance(_yaml_value(entry[1]), list):
                    raise ValueError
                list_count += 1
                output.append(line)
                continue
            if list_key and not list_count:
                raise ValueError
            list_key, list_count = None, 0
            match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_.-]*):[ ]*(.*)", body)
            if not match:
                raise ValueError
            key, value = match.groups()
            if key in seen or key in {"http", "http.host", "http.publish_port", "plugins", "plugins.security", "plugins.security.ssl", "plugins.security.ssl.http"}:
                raise ValueError
            if any(key.startswith(target + ".") or target.startswith(key + ".") for target in targets):
                raise ValueError
            if any(key.startswith(other + ".") or other.startswith(key + ".") for other in seen):
                raise ValueError
            seen.add(key)
            # This is a conservative syntax boundary, not a general YAML parser.
            if any(c in value for c in "&*!|>{}`%") or value.startswith("{"):
                raise ValueError
            if not value or value.startswith("#"):
                if key in targets:
                    raise ValueError
                list_key = key
            else:
                parsed = _yaml_value(value)
                if key == "http.bind_host" and parsed not in ("127.0.0.1", ["127.0.0.1"], ["127.0.0.1", p.indexer_ip]):
                    raise ValueError
                if key == "http.port" and parsed != "9200":
                    raise ValueError
                if key == "http.publish_host" and parsed != "127.0.0.1":
                    raise ValueError
                if key in targets and key.startswith("plugins.") and not isinstance(parsed, str):
                    raise ValueError
            if key in targets:
                output.append(f"{key}: {targets[key]}" + (newline if line.endswith(newline) else ""))
            else:
                output.append(line)
        if list_key and not list_count:
            raise ValueError
        missing = [key for key in targets if key not in seen]
        if missing:
            if output and not output[-1].endswith(newline):
                output.append(newline)
            output.extend(f"{key}: {targets[key]}{newline}" for key in missing)
        return "".join(output).encode("utf-8")
    except (ValueError, UnicodeError):
        raise SetupError("config_unsupported") from None


def archive_ca_members(raw: bytes, p: Profile) -> tuple[bytes, bytes]:
    """Offline bytes convenience only; live callers use read_vendor_ca_archive.

    Never obtain this argument by reading/copying/hashing a live CA archive.
    """
    if not isinstance(raw, bytes):
        raise SetupError("archive_invalid")
    return read_vendor_ca_archive(io.BytesIO(raw), p)


def _archive_member(header: bytes, seen: set, p: Profile):
    """One shared closed header policy for seek-only and sequential tar intake."""
    if len(seen) >= 128:
        raise ValueError
    member = tarfile.TarInfo.frombuf(header, encoding="utf-8", errors="strict")
    name = member.name.removesuffix("/") if member.isdir() else member.name
    if not _path(name, absolute=False) or name in seen:
        raise ValueError
    seen.add(name)
    if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE) or member.linkname:
        raise ValueError
    if member.size < 0 or member.size > 1024 * 1024 or member.isdir() and member.size:
        raise ValueError
    if name in (p.ca_member, p.key_member) and (not member.isfile() or not member.size):
        raise ValueError
    return name, member


def _selected_ca(selected: dict, p: Profile) -> tuple[bytes, bytes]:
    if set(selected) != {p.ca_member, p.key_member}:
        raise ValueError
    if hashlib.sha256(selected[p.ca_member]).hexdigest() != p.expected_ca_file_sha256:
        raise ValueError
    return selected[p.ca_member], selected[p.key_member]


class _GzipForwardReader:
    """Single gzip member, bounded raw input/output, no decoded read-ahead."""

    def __init__(self, source: BinaryIO, raw_size: int):
        self.source = source
        self.remaining = raw_size
        self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.pending = b""
        self.decoded = 0

    def read(self, size: int) -> bytes:
        if not 0 < size <= 65536:
            raise ValueError
        chunks = []
        while size and not self.decoder.eof:
            if not self.pending:
                if not self.remaining:
                    raise ValueError  # Missing gzip end/checksum, even after tar EOF.
                wanted = min(65536, self.remaining)
                self.pending = self.source.read(wanted)
                if not isinstance(self.pending, bytes) or not 0 < len(self.pending) <= wanted:
                    raise ValueError
                self.remaining -= len(self.pending)
            old_length = len(self.pending)
            chunk = self.decoder.decompress(self.pending, min(size, 32 * 1024 * 1024 - self.decoded + 1))
            self.pending = self.decoder.unconsumed_tail
            self.decoded += len(chunk)
            if self.decoded > 32 * 1024 * 1024:
                raise ValueError
            if self.decoder.eof and (self.decoder.unused_data or self.remaining):
                raise ValueError  # Concatenation and all trailing compressed bytes refuse.
            if not chunk and not self.decoder.eof and len(self.pending) == old_length:
                raise ValueError
            chunks.append(chunk)
            size -= len(chunk)
        return b"".join(chunks)


def read_vendor_ca_archive(source: BinaryIO, p: Profile) -> tuple[bytes, bytes]:
    """Select CA/key from a trusted unbuffered plain or single-member gzip inode.

    Plain tar delegates to the seek-only reader. Gzip necessarily decodes skipped
    plaintext; discard it in <=64 KiB chunks without interpreting, persisting or
    logging it. Only the selected bodies (<=1 MiB each) are retained. Raw and
    decoded sizes each cap at 32 MiB. Fully validate tar end padding and gzip CRC/
    EOF so trailing streams/data cannot hide records. No filesystem writes occur.
    Caller performs provenance/stat checks; source offset/lifetime are preserved.
    """
    try:
        if isinstance(source, (io.BufferedReader, io.BufferedRandom)) or not source.seekable() or not source.readable():
            raise ValueError
        original = source.tell()
        try:
            source.seek(0, io.SEEK_END)
            raw_size = source.tell()
            if not 0 < raw_size <= 32 * 1024 * 1024:
                raise ValueError
            source.seek(0)
            magic = source.read(2)
            if magic != b"\x1f\x8b":
                return read_archive_ca_members(source, p)
            source.seek(0)
            stream = _GzipForwardReader(source, raw_size)

            def take(length, *, retain):
                chunks = []
                while length:
                    chunk = stream.read(min(65536, length))
                    if not chunk:
                        raise ValueError
                    length -= len(chunk)
                    if retain:
                        chunks.append(chunk)
                return b"".join(chunks) if retain else None

            seen, selected = set(), {}
            while True:
                header = take(512, retain=True)
                if header == b"\0" * 512:
                    if take(512, retain=True) != b"\0" * 512:
                        raise ValueError
                    while trailer := stream.read(65536):
                        if any(trailer):
                            raise ValueError
                    if stream.decoded % 512:
                        raise ValueError
                    return _selected_ca(selected, p)
                name, member = _archive_member(header, seen, p)
                if name in (p.ca_member, p.key_member):
                    selected[name] = take(member.size, retain=True)
                else:
                    take(member.size, retain=False)
                take(-member.size % 512, retain=False)
        finally:
            source.seek(original)
    except (AttributeError, ValueError, OSError, EOFError, UnicodeError, tarfile.TarError, zlib.error):
        raise SetupError("archive_invalid") from None


def read_archive_ca_members(source: BinaryIO, p: Profile) -> tuple[bytes, bytes]:
    """Read only two bodies from a seekable, unbuffered uncompressed tar inode.

    The host caller verifies ownership, modes, inode identity and stat stability
    and supplies an unbuffered binary file (e.g. os.fdopen(fd, 'rb', buffering=0)).
    Buffered readers are refused because their read-ahead may ingest other bodies.
    The source remains open and its initial offset is restored, even on rejection.
    No extraction, whole-archive copy or whole-archive hash takes place here.
    Only ordinary regular-file/directory headers are supported; extension records
    (including PAX, GNU long-name and sparse records) require bodies and reject.
    """
    limit = 32 * 1024 * 1024
    block = 512
    try:
        if isinstance(source, (io.BufferedReader, io.BufferedRandom)) or not source.seekable() or not source.readable():
            raise ValueError
        original = source.tell()
        try:
            source.seek(0, io.SEEK_END)
            size = source.tell()
            if size < 2 * block or size > limit or size % block:
                raise ValueError

            def read_exact(length):
                chunks = []
                while length:
                    chunk = source.read(length)
                    if not isinstance(chunk, bytes) or not chunk or len(chunk) > length:
                        raise ValueError
                    chunks.append(chunk)
                    length -= len(chunk)
                return b"".join(chunks)

            selected = {}
            seen = set()
            offset = 0
            ended = False
            while offset + block <= size:
                source.seek(offset)
                header = read_exact(block)
                if header == b"\0" * block:
                    # Two zero blocks end the archive. The remaining record
                    # padding must be entirely zero; never parse hidden members.
                    if offset + 2 * block > size or read_exact(block) != b"\0" * block:
                        raise ValueError
                    for _ in range((size - offset - 2 * block) // block):
                        if read_exact(block) != b"\0" * block:
                            raise ValueError
                    ended = True
                    break
                name, member = _archive_member(header, seen, p)
                next_offset = offset + block + ((member.size + block - 1) // block) * block
                if next_offset > size:
                    raise ValueError
                if name in (p.ca_member, p.key_member):
                    selected[name] = read_exact(member.size)
                # Skip all unselected bodies and all body padding by seek only.
                offset = next_offset
            if not ended:
                raise ValueError
            return _selected_ca(selected, p)
        finally:
            source.seek(original)
    except (AttributeError, ValueError, OSError, EOFError, UnicodeError, tarfile.TarError):
        raise SetupError("archive_invalid") from None
