"""Synthetic authoring fixtures; never evidence or pilot ground truth."""
import hashlib
import io
import json
import warnings
import zipfile

from aegis_verify.scenario_loader import parse_scenario_yaml
from aegis_verify.validation.contracts import EvaluationProfile
from aegis_verify.validation.results import profile_fingerprint, scenario_fingerprint


SCENARIO = b'''id: SCN-900
name: Catalog authoring sample
version: 0.1.0
status: draft
description: Illustrative output-only script for package authoring review.
safety:
  destructive: false
  authorization_required: true
  notes: Authoring sample only; execution requires separate approval.
expected_sources: [wazuh]
expected_outcome: detected
assertions:
  - id: SCN-900-A01
    description: Illustrative reviewed detection expectation.
    source: wazuh
'''


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def sample_members():
    manifest = parse_scenario_yaml(SCENARIO.decode(), source_name="scenario.yaml")
    profile = {
        "profile_id": "scn900-authoring-example", "profile_version": "0.1.0",
        "scenario_id": "SCN-900", "scenario_version": "0.1.0",
        "scenario_fingerprint": scenario_fingerprint(manifest),
        "rules": [{"assertion_id": "SCN-900-A01", "role": "detection",
                   "capability": "unsupported", "reason_code": "authoring_sample_only"}],
    }
    profile = EvaluationProfile.model_validate(profile)
    members = {"scenario.yaml": SCENARIO, "profile.json": json_bytes(profile.model_dump(mode="json")),
               "README.md": b"Authoring sample only. Does not provide detection evidence.\n",
               "payload/demo.ps1": b"Write-Output 'AEGIS catalog authoring sample'\n"}
    metadata = {"format": "aegis-scenario-package/1", "scenario_id": "SCN-900", "version": "0.1.0",
                "platform": "windows", "runner": "windows-powershell-script@1",
                "entrypoint": "payload/demo.ps1", "cleanup": None, "timeout_seconds": 120,
                "profile_fingerprint": profile_fingerprint(profile),
                "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()}}
    members["package.json"] = json_bytes(metadata)
    return members


def inventory(members):
    metadata = json.loads(members["package.json"])
    metadata["files"] = {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()
                         if name != "package.json"}
    members["package.json"] = json_bytes(metadata)
    return members


def package_zip(members=None, *, compression=zipfile.ZIP_STORED, extra=()):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, raw in (sample_members() if members is None else members).items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            # Keep hostile names byte-for-byte on Windows (ZipInfo normalizes separators).
            info.filename = info.orig_filename = name
            info.compress_type = compression
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
        for info, raw in extra:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(info, raw)
    return output.getvalue()


def build_sample():
    """Convenient valid synthetic upload for Manager integration tests."""
    return package_zip()


def forged_size(raw, member, size):
    """Lie in both ZIP headers while retaining the actual compressed bytes."""
    import struct
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        offset = archive.getinfo(member).header_offset
    output = bytearray(raw)
    struct.pack_into("<L", output, offset + 22, size)
    cursor = 0
    while True:
        cursor = raw.find(b"PK\x01\x02", cursor)
        if cursor < 0:
            raise AssertionError("missing member")
        name_size = struct.unpack_from("<H", raw, cursor + 28)[0]
        if raw[cursor + 46:cursor + 46 + name_size] == member.encode():
            struct.pack_into("<L", output, cursor + 24, size)
            return bytes(output)
        cursor += 4
