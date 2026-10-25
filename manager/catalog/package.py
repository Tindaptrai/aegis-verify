"""Bounded, no-extraction catalog package validation. Never executes a payload."""
from dataclasses import dataclass
import binascii
import hashlib
import io
import re
import stat
import struct
from typing import BinaryIO
import zipfile
import zlib

from pydantic import ValidationError

from aegis_verify.intake.errors import IntakeError
from aegis_verify.intake.io import decode_config
from aegis_verify.scenario_loader import ScenarioLoadError, parse_scenario_yaml
from aegis_verify.validation._inputs import validate_manifest_profile
from aegis_verify.validation.contracts import EvaluationProfile
from aegis_verify.validation.errors import ValidationEngineError
from aegis_verify.validation.results import profile_fingerprint

from .errors import CatalogError

MAX_ZIP_BYTES = 20 * 1024 * 1024
MAX_EXPANDED_BYTES = 100 * 1024 * 1024
MAX_MEMBERS = 200
MAX_MEMBER_BYTES = 1024 * 1024
MAX_SCENARIO_BYTES = 256 * 1024
MAX_COMPRESSION_RATIO = 100
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._ -]*\Z")
_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z", re.I)
_ROOT = frozenset({"package.json", "scenario.yaml", "profile.json", "README.md"})
_EXTENSIONS = frozenset({"ps1", "json", "txt", "yaml", "yml"})
_ARCHIVE_EXTENSIONS = frozenset({"zip", "gz", "gzip", "tar", "tgz", "bz2", "xz", "7z", "rar", "jar"})
_FIELDS = frozenset({"format", "scenario_id", "version", "platform", "runner", "entrypoint",
                     "cleanup", "timeout_seconds", "profile_fingerprint", "files"})


@dataclass(frozen=True)
class ValidatedPackage:
    sha256: str
    metadata: dict
    files: list[dict]
    contents: dict[str, bytes]


def _fail(code):
    raise CatalogError(code, status=413 if code == "package_too_large" else 400, codes=[code])


def _safe_path(name):
    if type(name) is not str or len(name) > 240 or "\\" in name:
        _fail("invalid_path")
    parts = name.split("/")
    if any(not _COMPONENT.fullmatch(part) or part.endswith((".", " ")) or _DEVICE.fullmatch(part)
           for part in parts):
        _fail("invalid_path")
    return name


def _read_stream(stream):
    output = bytearray()
    while True:
        chunk = stream.read(min(65536, MAX_ZIP_BYTES + 1 - len(output)))
        if not isinstance(chunk, bytes):
            _fail("invalid_zip")
        if not chunk:
            return bytes(output)
        output.extend(chunk)
        if len(output) > MAX_ZIP_BYTES:
            _fail("package_too_large")


def _central_directory(raw):
    """Count actual directory records before ZipFile allocates its entry objects."""
    end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
    if end < 0 or end + 22 > len(raw):
        _fail("invalid_zip")
    disk, start_disk, disk_count, count, size, offset, comment = struct.unpack_from("<4H2LH", raw, end + 4)
    if disk or start_disk or disk_count != count or end + 22 + comment != len(raw) or offset + size != end:
        _fail("invalid_zip")
    if count > MAX_MEMBERS:
        _fail("too_many_members")
    cursor, actual = offset, 0
    while cursor < end:
        if cursor + 46 > end or raw[cursor:cursor + 4] != b"PK\x01\x02":
            _fail("invalid_zip")
        name_size, extra_size, comment_size = struct.unpack_from("<3H", raw, cursor + 28)
        cursor += 46 + name_size + extra_size + comment_size
        actual += 1
        if actual > MAX_MEMBERS:
            _fail("too_many_members")
    if cursor != end or actual != count:
        _fail("invalid_zip")
    return offset


def _member(raw, info, directory_offset, expanded):
    offset = info.header_offset
    if offset < 0 or offset + 30 > directory_offset or raw[offset:offset + 4] != b"PK\x03\x04":
        _fail("invalid_zip")
    flags, method = struct.unpack_from("<2H", raw, offset + 6)
    crc, compressed_size, declared_size = struct.unpack_from("<3L", raw, offset + 14)
    name_size, extra_size = struct.unpack_from("<2H", raw, offset + 26)
    start = offset + 30 + name_size + extra_size
    end = start + info.compress_size
    if flags != info.flag_bits or method != info.compress_type or end > directory_offset:
        _fail("invalid_zip")
    if raw[offset + 30:offset + 30 + name_size] != info.orig_filename.encode("ascii"):
        _fail("invalid_zip")
    if not flags & 8 and (crc, compressed_size, declared_size) != (info.CRC, info.compress_size, info.file_size):
        _fail("invalid_zip")
    limit = min(MAX_MEMBER_BYTES, MAX_SCENARIO_BYTES if info.filename == "scenario.yaml" else MAX_MEMBER_BYTES)
    data = bytearray()
    decoder = zlib.decompressobj(-15) if method == zipfile.ZIP_DEFLATED else None
    for cursor in range(start, end, 65536):
        block = raw[cursor:min(cursor + 65536, end)]
        # max_length bounds actual output even when the central directory lies.
        decoded = decoder.decompress(block, limit + 1 - len(data)) if decoder else block
        data.extend(decoded)
        if len(data) > limit:
            _fail("member_too_large")
        if expanded + len(data) > MAX_EXPANDED_BYTES:
            _fail("expanded_too_large")
        if len(data) > MAX_COMPRESSION_RATIO * max(1, info.compress_size):
            _fail("compression_ratio")
    if decoder and (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail):
        _fail("invalid_zip")
    if len(data) != info.file_size or binascii.crc32(data) != info.CRC:
        _fail("invalid_zip")
    return bytes(data), (offset, end)


def _json(raw):
    try:
        return decode_config(raw, stage="catalog")
    except IntakeError:
        _fail("invalid_json")


def _metadata(contents):
    metadata = _json(contents["package.json"])
    if set(metadata) != _FIELDS:
        _fail("invalid_metadata")
    if (metadata["format"] != "aegis-scenario-package/1" or metadata["platform"] != "windows" or
            metadata["runner"] != "windows-powershell-script@1" or
            type(metadata["timeout_seconds"]) is not int or not 1 <= metadata["timeout_seconds"] <= 600 or
            type(metadata["scenario_id"]) is not str or not re.fullmatch(r"SCN-[0-9]{3}", metadata["scenario_id"]) or
            type(metadata["version"]) is not str or len(metadata["version"]) > 128 or not _VERSION.fullmatch(metadata["version"]) or
            type(metadata["profile_fingerprint"]) is not str or not _DIGEST.fullmatch(metadata["profile_fingerprint"])):
        _fail("invalid_metadata")
    inventory = metadata["files"]
    if type(inventory) is not dict or any(type(digest) is not str or not _DIGEST.fullmatch(digest) for digest in inventory.values()):
        _fail("invalid_metadata")
    for name in inventory:
        _safe_path(name)
    for field in ("entrypoint", "cleanup"):
        name = metadata[field]
        if name is None and field == "cleanup":
            continue
        if type(name) is not str or name not in inventory or not name.startswith("payload/") or not name.endswith(".ps1"):
            _fail("invalid_metadata")
    if set(inventory) != set(contents) - {"package.json"}:
        _fail("inventory_mismatch")
    if any(hashlib.sha256(contents[name]).hexdigest() != digest for name, digest in inventory.items()):
        _fail("hash_mismatch")
    return metadata


def _validate(raw):
    directory_offset = _central_directory(raw)
    contents, seen, spans, expanded = {}, set(), [], 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for info in archive.infolist():
            name = _safe_path(info.orig_filename)
            if name.casefold() in seen:
                _fail("duplicate_member")
            seen.add(name.casefold())
            mode = info.external_attr >> 16
            if info.is_dir() or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)) or info.external_attr & 0x10:
                _fail("unsupported_member")
            if info.flag_bits & (1 | 64):
                _fail("encrypted_member")
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or info.flag_bits & ~0x80e:
                _fail("unsupported_compression")
            extension = name.rsplit(".", 1)[-1].lower()
            if extension in _ARCHIVE_EXTENSIONS:
                _fail("nested_archive")
            if name not in _ROOT and (not name.startswith("payload/") or extension not in _EXTENSIONS):
                _fail("unsupported_member")
            limit = min(MAX_MEMBER_BYTES, MAX_SCENARIO_BYTES if name == "scenario.yaml" else MAX_MEMBER_BYTES)
            if info.file_size > limit:
                _fail("member_too_large")
            if expanded + info.file_size > MAX_EXPANDED_BYTES:
                _fail("expanded_too_large")
            if info.file_size > MAX_COMPRESSION_RATIO * max(1, info.compress_size):
                _fail("compression_ratio")
            data, span = _member(raw, info, directory_offset, expanded)
            spans.append(span)
            if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"BZh", b"\xfd7zXZ\x00")) or data[257:262] == b"ustar":
                _fail("nested_archive")
            try:
                data.decode("utf-8")
            except UnicodeError:
                _fail("invalid_utf8")
            expanded += len(data)
            contents[name] = data
    spans.sort()
    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
        _fail("invalid_zip")
    if not _ROOT <= contents.keys():
        _fail("inventory_mismatch")
    metadata = _metadata(contents)
    try:
        manifest = parse_scenario_yaml(contents["scenario.yaml"].decode("utf-8"), source_name="scenario.yaml")
    except ScenarioLoadError:
        _fail("invalid_scenario")
    if len(manifest.name) > 512:
        _fail("invalid_scenario")
    if (manifest.id, manifest.version) != (metadata["scenario_id"], metadata["version"]):
        _fail("scenario_mismatch")
    profile_data = _json(contents["profile.json"])
    try:
        profile = EvaluationProfile.model_validate(profile_data)
    except (ValidationError, ValueError, RecursionError):
        _fail("invalid_profile")
    try:
        validate_manifest_profile(manifest, profile)
    except ValidationEngineError:
        _fail("profile_mismatch")
    if profile_fingerprint(profile) != metadata["profile_fingerprint"]:
        _fail("profile_mismatch")
    metadata["name"] = manifest.name
    files = [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
             for name, data in sorted(contents.items())]
    return ValidatedPackage(hashlib.sha256(raw).hexdigest(), metadata, files, contents)


def validate_package(stream: BinaryIO) -> ValidatedPackage:
    """Read at most 20 MiB + one sentinel byte; never use an uploaded filename."""
    try:
        return _validate(_read_stream(stream))
    except CatalogError:
        raise
    except (OSError, ValueError, TypeError, AttributeError, OverflowError, RecursionError,
            zipfile.BadZipFile, zipfile.LargeZipFile, struct.error, zlib.error):
        raise CatalogError("invalid_zip", codes=["invalid_zip"]) from None
