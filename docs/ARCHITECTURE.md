# AEGIS Verify Architecture

## Design principles

1. Fixture first: CI and local tests must not require a live lab.
2. Evidence first: every conclusion references one or more evidence IDs.
3. No inference from absence: missing fields are `null`; missing evidence is reported.
4. Source isolation: parsers know vendor formats; the validation engine does not.
5. Safe replay: scenario execution must be bounded, reversible, and approved.

## Data flow

```text
Evidence bundle directory
  ├─ inputs.json      one entry per file: parser key, source_ref, SHA-256, context
  ├─ evidence files   Wazuh JSON, Suricata EVE, pfSense filterlog, Cowrie JSON
  ├─ profile.json     EvaluationProfile (or --profile)
  └─ context.json     run window and bindings (or --context)
          │
          ▼
Bundle intake: hash check → registry → one parser per file → ledger
          │
          ▼
Canonical Event v2
          │
          ├──────── Scenario YAML ground truth (scenarios/)
          ├──────── EvaluationProfile: rules, bindings, correlation windows
          │
          ▼
Validation Engine
          │
          ├─ Detected
          ├─ Prevented
          ├─ Missing telemetry
          ├─ False negative
          └─ Inconclusive
          │
          ▼
CLI JSON/text report (evaluation, ledger, fingerprints, evidence timeline)
          │
          ├─► aegis compare     two reports → regression status
          └─► aegis dashboard   read-only view of a report directory
```

Evidence reaches a bundle as exported files: fixtures in CI, private lab
exports for real runs. The optional Operations mode can collect a bounded
window from the Wazuh Indexer into a bundle, but it never evaluates, runs a
scenario or changes rules.

## Component boundaries

### Connectors (`connectors/`)

Each connector parses only its source format and emits canonical events. A connector
must retain a stable `raw_event_ref` that lets a reviewer trace the normalized event
back to the exact input bytes, plus the SHA-256 of those bytes. Parsers reject
shapes outside their reviewed profile with fixed-vocabulary diagnostics that never
echo source values. Source time is used as event time; receipt or ingest time is
kept separately and never substituted.

The Wazuh package also holds a bounded HTTPS reader for the Indexer and manager
snapshots, used only by Operations mode.

### Canonical Event Model (`backend/app/models`)

Canonical Event v2 (Issue #1, lossless timestamps in #15) represents event identity,
nanosecond source timestamp, ingest time, source, asset/user/network/process/action/
rule/signature context, ATT&CK technique and the raw evidence reference. Optional
data remains `null`; parsers do not invent values.

### Bundle intake (`backend/app/intake`)

Reads `inputs.json`, checks each file's SHA-256 before parsing, dispatches to
exactly the parser key it names with that parser's closed context, and builds a
ledger of parsed and skipped records. Optional `display_label` and `derived_from`
describe where bytes came from without changing evidence identity.

### Scenario manifest and evaluation profile (`scenarios/`)

A manifest identifies safe test behavior, expected sources, expected outcome and
assertion IDs; its schema is Issue #2. Ground truth changes require explicit owner
approval. An `EvaluationProfile` binds each assertion to a role (telemetry,
detection, prevention), a source type, predicates on canonical fields, reviewed
rule or signature literals, and correlation to a telemetry anchor through join
fields and a time window. Lab-specific values (addresses, ports, rule trackers)
enter through `context.json` bindings, not the profile. The profile pins the
manifest's fingerprint, so a manifest edit forces a profile review.

### Validation Engine (`backend/app/validation`)

The engine accepts a manifest, canonical events, a profile and a context. It never
reads source-specific fields. Every assertion returns an outcome, a reason code and
supporting evidence IDs or witness pairs, and distinguishes absent telemetry from
present telemetry with a missing detection. `False negative` requires a caller
declaration that collection was complete for the scope; otherwise absence stays
`Inconclusive`. Inputs, profile, scope and event set are fingerprinted.

### Interfaces

- `aegis validate` (`backend/app/cli`): evaluates one bundle; JSON or text report
  with an ordered evidence timeline. Exit codes separate pass, fail,
  `Inconclusive`, input errors and internal errors.
- `aegis compare` (`backend/app/compare`): compares two reports of the same scenario,
  profile and bindings. Built for Gap → Fix; `Regression Passed` requires a
  `false_negative` assertion to become `satisfied`.
- `aegis dashboard` (`backend/app/dashboard`, `frontend/`): standard-library HTTP on
  loopback serving a report directory to a React page. Read-only by default;
  optional Operations mode adds Wazuh agent inventory and bounded historical
  collection behind a private config.

There is no FastAPI service; no new Python dependency was needed.

## Layout

```text
backend/app/models      Canonical event, precise timestamps, scenario model
backend/app/intake      Bundle manifest, registry, ledger
backend/app/validation  Profile/context contracts, engine, fingerprints
backend/app/cli         validate / compare / dashboard commands
backend/app/compare     Report comparison
backend/app/dashboard   Read-only server, Operations jobs
backend/app/demo        SCN-001 demo kit and study binding
backend/tests/          Unit, integration and CLI subprocess tests
connectors/             Wazuh, Suricata, pfSense, Cowrie parsers; bounded Wazuh reader
scenarios/              Reviewed ground truth; profiles/ for public evaluation profiles
detections/             Wazuh and Suricata detection content templates
tests/fixtures/         Sanitized or clearly synthetic evidence only
frontend/               Vite + React results dashboard
```

## V1 boundary

Implemented in V1: the bounded Wazuh Indexer reader behind Operations mode. Not
implemented: continuous ingestion of Suricata EVE, pfSense syslog or Cowrie
streams, and any automatic scenario execution. Real lab runs so far (SCN-002,
2026-09-22) used exported files evaluated offline. Offline files, including direct
EVE JSONL, remain first class. Any live adapter must reuse the canonical model and
validation engine rather than bypassing them.
