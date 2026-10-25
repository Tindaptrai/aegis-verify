"""Build deterministic SCN-900 authoring material. Never executes the payload."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import zipfile

from aegis_verify.scenario_loader import parse_scenario_yaml
from aegis_verify.validation.contracts import EvaluationProfile
from aegis_verify.validation.results import profile_fingerprint, scenario_fingerprint


def _json(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def build_sample() -> bytes:
    """Return an illustrative ZIP, independent of existing scenario ground truth."""
    scenario = b'''id: SCN-900
name: Catalog authoring sample
version: 0.1.0
status: draft
description: Illustrative output-only PowerShell authoring material; not lab evidence.
safety:
  destructive: false
  authorization_required: true
  notes: Review independently and obtain lab approval before any execution.
expected_sources: [wazuh]
expected_outcome: detected
assertions:
  - id: SCN-900-A01
    description: Illustrative telemetry expectation for a separately approved lab.
    source: wazuh
  - id: SCN-900-A02
    description: Illustrative detection expectation; no detection result is claimed.
    source: wazuh
tags: [authoring-sample]
'''
    manifest = parse_scenario_yaml(scenario.decode(), source_name="scenario.yaml")
    scope = [{"field": "hostname", "op": "eq", "binding": "target_host"}]
    profile = EvaluationProfile.model_validate({
        "profile_schema_version": "0.1.0", "profile_id": "scn900-authoring-example",
        "profile_version": "0.1.0", "scenario_id": "SCN-900", "scenario_version": "0.1.0",
        "scenario_fingerprint": scenario_fingerprint(manifest),
        "rules": [
            {"assertion_id": "SCN-900-A01", "role": "telemetry", "capability": "supported",
             "source_type": "wazuh", "scope": scope,
             "match": [{"field": "event_action", "op": "eq", "value": "observed"}]},
            {"assertion_id": "SCN-900-A02", "role": "detection", "capability": "supported",
             "source_type": "wazuh", "scope": scope,
             "match": [{"field": "rule_id", "op": "eq", "value": "authoring-example-only"}],
             "correlation": {"anchor_assertion_id": "SCN-900-A01",
                             "join_pairs": [{"target_field": "hostname", "anchor_field": "hostname"}],
                             "min_delta_ns": 0, "max_delta_ns": 60000000000}},
        ],
    })
    contents = {
        "scenario.yaml": scenario,
        "profile.json": _json(profile.model_dump(mode="json")),
        "README.md": b'''# SCN-900 catalog authoring sample

This separate, draft sample is illustrative authoring material, not an installed
pilot, production evidence, a validated detection, or proof of script safety.
The payload only writes one line to standard output. It does not access files,
networks, credentials, policies or rules. Manager never executes imported files.

The profile uses a target_host runtime binding and an illustrative rule literal.
No host, address or connector endpoint is configured. A future approved lab must
review its own detection content, provide bindings and evidence, and obtain
authorization separately. Publishing only makes the package available in Catalog.
''',
        "payload/demo.ps1": b"Write-Output 'AEGIS catalog authoring sample'\n",
    }
    metadata = {
        "format": "aegis-scenario-package/1", "scenario_id": "SCN-900", "version": "0.1.0",
        "platform": "windows", "runner": "windows-powershell-script@1",
        "entrypoint": "payload/demo.ps1", "cleanup": None, "timeout_seconds": 120,
        "profile_fingerprint": profile_fingerprint(profile),
        "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in contents.items()},
    }
    contents["package.json"] = _json(metadata)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(contents.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, raw)
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Destination .zip path (explicitly overwritten)")
    args = parser.parse_args()
    raw = build_sample()
    args.output.write_bytes(raw)
    args.output.with_suffix(args.output.suffix + ".sha256").write_text(
        hashlib.sha256(raw).hexdigest() + "  " + args.output.name + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
