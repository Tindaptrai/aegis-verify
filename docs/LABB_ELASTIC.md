# Offline Elastic integration for Lab B

Lab B uses a distinct canonical `elastic` source. It evaluates exported evidence
through the existing bundle intake and engine; it does not introduce a live
Elastic reader, execute scenarios automatically or parse binary EVTX. Keep EVTX
as original comparison evidence and retain the full exported search hits.

The new SCN-005 and SCN-006 manifests are separate reviewable drafts. Existing
SCN-001 through SCN-004 and their profiles retain their original ground truth.
Implementation and a successful private run do not imply upstream review/merge,
independent operator acceptance or production stability.

## Explicit byte parsers

| Parser key | Input |
| --- | --- |
| `elastic-sysmon1-v1` | One exported search hit containing native Windows Sysmon process-creation XML. |
| `elastic-sysmon3-v1` | One exported search hit containing native Windows Sysmon connection XML. |
| `elastic-powershell4104-v1` | One exported search hit containing complete single-part PowerShell script-block XML. |
| `elastic-security-alert-v1` | One exported flat dotted Elastic Security alert hit, including rule identity and native Windows evidence. |

Each parser receives `source_ref`, `environment_id` and `ingested_at`. The bundle
entry has only the closed `ingested_at` context. Extract exact individual JSONL
line bytes into separate input files, retain the parent export/hash/byte range in
private provenance, and give each file a unique safe `source_ref`. Do not
reserialize an input and describe it as its original bytes. An unchanged hit's
`_index`, `_id`, native host/channel/provider/record ID and parser provenance let
the reviewer trace an EID back to source artifacts.

For a line selection whose bytes differ from the full parent file, use
`derived_from: {parent_sha256: <parent hash>, extraction: physical-line-bytes-v1}`.
This labels the extraction in the ledger/timeline; it does not make the engine
verify an external parent. Keep byte ranges, exact line hashes and a separate
parent/slice audit. An unchanged one-record export used in full needs no artificial
self-parent declaration (equal parent/input hashes are rejected).

The parsers use Windows `event.original` XML as the native authority and check
exported aliases when present. They preserve unknown fields through the hashed
raw reference; absent optional canonical facts remain `null`. Source-event
parsers reject detection-alert shapes and alert parsing uses a separate producing
provider, `elastic-security`. This prevents copied alert telemetry from standing
in for a Windows source record.

Windows canonical timestamp is XML `System.TimeCreated`, at its original
precision. Sysmon `UtcTime`, normalized Elastic `@timestamp` and Elastic ingest
timestamps remain independent provenance. Alert canonical time is
`kibana.alert.start`; copied original Windows time is not substituted for it.
The caller's `ingested_at` is the bundle intake observation time. Review parser
provenance for the other clocks and do not repair timestamps in raw evidence.

See [Elastic parser contract](ELASTIC_PARSER.md) for supported shapes, mapping,
rejections and precise identity rules.

## Profiles and private bundle evaluation

- [SCN-005 PowerShell profile](../scenarios/profiles/scn-005/README.md): process
  and complete script telemetry, followed by the reviewed benign Elastic rule
  within the pinned 0–120 second interval.
- [SCN-006 HTTP visibility profile](../scenarios/profiles/scn-006/README.md):
  endpoint connection, Suricata marker detection and pfSense allowed telemetry;
  no prevention claim.

Before execution, record the authorization, payload/runner/rule hashes, manifest
and profile fingerprints, context bindings, clock/health thresholds and the
observation interval. After execution, preserve native artifacts and complete
paginated exports, reconcile original IDs and source-document alert ancestry,
then assemble a private bundle outside every Git working tree:

```text
private-run/
  bundle/
    inputs.json
    profile.json
    context.json
    evidence/              exact bytes named in inputs.json
  receipt.json
  provenance.json
  raw/                     original EVTX, EVE and filterlog as applicable
  siem-export/             original full exports and pagination metadata
```

`inputs.json` uses bundle schema `0.1.0`, the real `environment_id` and one entry
per file with `path`, `source_ref`, `parser`, exact `sha256` and the closed context.
Bindings come from the run receipt and source facts, not from public profile edits.
Use the matching scenario path and private bundle:

```powershell
aegis validate --scenario scenarios/SCN-005-powershell-elastic-lab-b.yaml --fixture <private-bundle> --format json
aegis validate --scenario scenarios/SCN-006-http-visibility-lab-b.yaml --fixture <private-bundle> --format json
```

Keep stdout JSON, stderr and exit code, and replay the same frozen bundle. Inspect
every assertion's evidence IDs/witness pairs against the ledger, exact raw hashes
and independent native reconciliation. `Detected` means the bounded profile was
satisfied; it does not establish whole-SIEM completeness. The canonical engine
joins hostname/PID/time or network tuple/time. Exact Elastic ancestor document
linkage and native EVTX identity are separately audited, not engine join fields.

A missing alert remains `Inconclusive` unless a justified complete-for-scope
declaration is supplied with all required fingerprints and assurances. Do not
infer completeness from a populated dashboard or a scoped ID match alone.
Neither a baseline without the target payload nor a replay is an additional
approved live marker run. A regression requires compatible before/after reports
that actually transition from `false_negative` to `satisfied`.
