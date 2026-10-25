# Catalog package authoring

A Catalog ZIP is immutable authoring material for human review. Import validates
its structure and manifest/profile compatibility. Publishing makes that exact
version available in Catalog; it does not execute scripts, install detection
rules, certify safety, or establish a detection result. Lab execution and evidence
evaluation require separate authorization and reviewed evidence.

## Generate the separate sample

From an environment with the project installed (`python -m pip install -e .`):

```powershell
python scripts/create_catalog_sample.py SCN-900-0.1.0.zip
Get-FileHash SCN-900-0.1.0.zip -Algorithm SHA256
```

The explicit output path is overwritten, along with `SCN-900-0.1.0.zip.sha256`.
The generator uses fixed member timestamps, ordering, modes, encoding and stored
compression, so repeated calls produce identical bytes. Its Python interface is
`scripts.create_catalog_sample.build_sample() -> bytes`.

SCN-900 is separate illustrative material, not an installed scenario or pilot
ground truth. Its only payload is `Write-Output`, which prints one line. Its
profile illustrates telemetry and detection correlation using a `target_host`
runtime binding and an illustrative rule literal. It contains no evidence,
configured host, address, credentials or connector endpoint. No detection is
claimed by this package.

## Root layout and metadata

The ZIP has no wrapping directory or explicit directory entries:

```text
package.json
scenario.yaml
profile.json
README.md
payload/demo.ps1
```

`package.json` is a closed UTF-8 JSON object. Every field below is required and
additional fields are rejected:

```json
{
  "format": "aegis-scenario-package/1",
  "scenario_id": "SCN-900",
  "version": "0.1.0",
  "platform": "windows",
  "runner": "windows-powershell-script@1",
  "entrypoint": "payload/demo.ps1",
  "cleanup": null,
  "timeout_seconds": 120,
  "profile_fingerprint": "<64 lowercase hexadecimal characters>",
  "files": {
    "scenario.yaml": "<SHA-256 of exact member bytes>",
    "profile.json": "<SHA-256 of exact member bytes>",
    "README.md": "<SHA-256 of exact member bytes>",
    "payload/demo.ps1": "<SHA-256 of exact member bytes>"
  }
}
```

Only the displayed format, Windows platform and runner are supported. The runner
is metadata, not an installed execution capability. `timeout_seconds` must be
an integer from 1 through 600; a JSON boolean is not an integer. `scenario_id`
matches `SCN-` plus three digits and `version` uses three numeric semver parts
without leading zeroes and is at most 128 characters. Both must equal the manifest values.

`files` inventories every member except `package.json`, with the SHA-256 of its
exact uncompressed bytes. Missing, unlisted or changed members are rejected.
At least one `.ps1` file is required below `payload/`; `entrypoint` names one.
`cleanup` is either null or another inventoried payload `.ps1` path. Other payload
extensions are `.json`, `.txt`, `.yaml` and `.yml`. The extension spelling is
lowercase for entrypoint and cleanup. README and all payloads remain inert text.

`scenario.yaml` uses the existing `ScenarioManifest` schema, including
`status: draft`, non-destructive safety metadata, authorization requirement and
valid assertion/source relationships. The scenario display name is at most 512
characters. Publication does not rewrite YAML status.

`profile.json` uses the existing `EvaluationProfile` schema. Generate the
manifest and profile fingerprints with the existing functions, rather than
hashing JSON serialization directly:

```python
from aegis_verify.scenario_loader import parse_scenario_yaml
from aegis_verify.validation.contracts import EvaluationProfile
from aegis_verify.validation.results import scenario_fingerprint, profile_fingerprint

manifest = parse_scenario_yaml(manifest_text, source_name="scenario.yaml")
profile_data["scenario_fingerprint"] = scenario_fingerprint(manifest)
profile = EvaluationProfile.model_validate(profile_data)
package_metadata["profile_fingerprint"] = profile_fingerprint(profile)
```

Compatibility reuses the evaluator's structural validation: profile ID/version
binding to the manifest, manifest fingerprint, exact assertion coverage, required
outcome role, source mappings, predicates, reviewed detection literals and
correlation anchors. Target bindings remain unresolved until an approved run
provides context. Catalog does not invent a context, read evidence or evaluate
assertions. Duplicate keys in package/profile JSON and unsafe YAML constructs are
rejected by the existing strict loaders.

## Paths, ZIP encoding and budgets

Member paths use forward slashes, at most 240 characters, and ASCII components
beginning with a letter, digit, underscore or hyphen; remaining characters may
also include dots and spaces. No component ends in a dot or space. Empty, dot,
parent, absolute, drive, UNC, backslash, alternate-stream and Windows reserved
device names are rejected. Duplicate names and case-insensitive collisions are
rejected. Members must be regular files; directories, links and special files
are rejected. Only ZIP stored and deflate compression are accepted. Encryption,
unsupported compression, nested archive extensions/signatures and malformed ZIP
headers/checksums are rejected. All member contents must decode as UTF-8.

| Budget | Maximum |
| --- | ---: |
| Actual ZIP stream | 20 MiB |
| Expanded member total | 100 MiB |
| Members | 200 |
| Uncompressed/compressed ratio per member | 100 |
| Each text member | 1 MiB |
| `scenario.yaml` | 256 KiB |

Validation checks actual streamed input and actual decompressed output in
addition to advertised ZIP metadata. It scans directory record counts before
creating ZIP member objects, enforces decompression limits even when headers lie,
and never extracts untrusted paths to disk. The HTTP request envelope has its own
separate bounded allowance; see the [Catalog runbook](CATALOG_RUNBOOK.md).

## Validation errors

Errors contain fixed codes only, without parser snippets, source values or private
paths. ZIP stream overflow returns HTTP 413 (`package_too_large`). Other package
failures return HTTP 400 with a bounded report. Relevant codes are:

```text
invalid_zip package_too_large too_many_members member_too_large
expanded_too_large compression_ratio invalid_path duplicate_member
unsupported_member encrypted_member unsupported_compression nested_archive
invalid_utf8 invalid_json invalid_metadata inventory_mismatch hash_mismatch
invalid_scenario scenario_mismatch invalid_profile profile_mismatch
```

Keep original local authoring files to diagnose a failed import. Create a new
version when changing an imported package. Same identity, version and ZIP digest
is an idempotent replay; different bytes for an existing identity/version conflict.
