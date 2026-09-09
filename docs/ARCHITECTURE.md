# AEGIS Verify Architecture

## Design principles

1. Fixture first: CI and local tests must not require a live lab.
2. Evidence first: every conclusion references one or more evidence IDs.
3. No inference from absence: missing fields are `null`; missing evidence is reported.
4. Source isolation: parsers know vendor formats; the validation engine does not.
5. Safe replay: scenario execution must be bounded, reversible, and approved.

## V0 data flow

```text
Sanitized fixtures
  ├─ Wazuh JSON
  ├─ Suricata eve.json
  ├─ pfSense filterlog
  └─ Cowrie JSON
          │
          ▼
Source fixture parsers
          │
          ▼
Canonical Event Model
          │
          ├──────── Scenario YAML ground truth
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
CLI result + evidence timeline + run comparison
```

## Component boundaries

### Connectors

Each connector parses only its source format and emits canonical events. A connector
must retain a stable `raw_event_ref` that lets a reviewer trace the normalized event
back to the sanitized fixture.

### Canonical Event Model

The initial model is defined by GitHub Issue #1. At minimum it must represent event
identity, timestamp, source, asset/user/network/process/action/rule context, ATT&CK
technique, and raw evidence reference. Optional data remains `null`; parsers do not
invent values.

### Scenario manifest

A manifest identifies safe test behavior, expected telemetry sources, expected
outcomes, and validation assertions. Issue #2 will formalize and validate its schema.
Ground truth changes require explicit review.

### Validation Engine

The engine accepts a scenario and a list of canonical events. It never reads
source-specific fields. Every assertion returns a status plus supporting evidence
IDs, and distinguishes absent telemetry from present telemetry with a missing
detection.

### Interfaces

The CLI is the first supported interface. FastAPI and React may expose the same
domain results only after the fixture-driven CLI works end to end.

## Planned layout

```text
backend/app/       Domain model, validation engine, CLI, and later API
backend/tests/     Unit and integration tests for backend behavior
connectors/        Source-specific fixture and later live adapters
scenarios/         Version-controlled, reviewed ground truth
detections/        Wazuh and Suricata detection content
tests/fixtures/    Sanitized test evidence only
frontend/          Deferred results dashboard
```

## V1 boundary

Live Wazuh API/Indexer and continuous ingestion of Suricata EVE, pfSense syslog,
and Cowrie streams are V1 connectors. Offline sanitized files, including the
direct EVE JSONL fixtures introduced by Suricata B, remain part of V0. Live adapters
must reuse the canonical model and validation engine rather than bypassing them.
