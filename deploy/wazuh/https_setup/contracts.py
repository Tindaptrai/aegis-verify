"""Closed deployment input contracts; no host mutation or source-value diagnostics."""
from dataclasses import asdict, dataclass
import hashlib
import io
import ipaddress
import json
from pathlib import PurePosixPath
import re
import tarfile
import zlib


class SetupError(Exception):
    """Only fixed vocabulary may cross the public error boundary."""

    def __init__(self, code: str):
        safe = {"profile_invalid", "config_unsupported", "archive_invalid",
                "certificate_invalid", "openssl_failed", "firewall_mismatch"}
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
    """Read two pinned members in memory; never extract or read other bodies."""
    limit = 32 * 1024 * 1024
    member_limit = 1024 * 1024
    try:
        if len(raw) > limit:
            raise ValueError
        if raw.startswith(b"\x1f\x8b"):
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw = decoder.decompress(raw, limit + 1)
            if len(raw) > limit or not decoder.eof or decoder.unused_data:
                raise ValueError
        selected = {}
        seen = set()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", ignore_zeros=True) as tar:
            for index, member in enumerate(tar):
                name = member.name.removesuffix("/") if member.isdir() else member.name
                if index >= 128 or not _path(name, absolute=False) or name in seen:
                    raise ValueError
                seen.add(name)
                if not (member.isfile() or member.isdir()) or member.size < 0 or member.size > member_limit:
                    raise ValueError
                if name in (p.ca_member, p.key_member):
                    if not member.isfile() or not member.size:
                        raise ValueError
                    body = tar.extractfile(member)
                    if body is None:
                        raise ValueError
                    with body:
                        selected[name] = body.read(member_limit + 1)
                    if len(selected[name]) != member.size:
                        raise ValueError
        if set(selected) != {p.ca_member, p.key_member}:
            raise ValueError
        if hashlib.sha256(selected[p.ca_member]).hexdigest() != p.expected_ca_file_sha256:
            raise ValueError
        return selected[p.ca_member], selected[p.key_member]
    except (ValueError, OSError, EOFError, tarfile.TarError, zlib.error):
        raise SetupError("archive_invalid") from None
