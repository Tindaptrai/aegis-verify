# Lab B Elastic Integration Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement the scoped
> tasks; independent connector and contract tasks may run in parallel.

**Goal:** Evaluate authentic Lab B exports through AEGIS with explicit source and
profile contracts, meaningful tests, real reports and a reproducible private handoff.

**Architecture:** Four fixture-first Elastic parsers feed the existing canonical
model/intake/engine. Separate SCN-005/006 manifests and bound profiles preserve
the old Wazuh and prevention contracts. No live adapter or EVTX dependency.

**Tech Stack:** Existing Python/Pydantic/PyYAML/pytest; standard-library JSON/XML.

**Spec:** `docs/superpowers/specs/2026-10-19-lab-b-elastic-design.md`

## Global constraints

- No new runtime dependency, hard-coded lab addresses, secrets or private evidence.
- Existing SCN-001–004 ground truth and profiles stay byte-identical.
- Canonical Windows timestamp is original XML System.TimeCreated; alert time is
  kibana.alert.start. Retain other clocks separately, never rewrite source bytes.
- Four explicit parser keys; diagnostics never echo untrusted values.
- No complete-for-scope declaration inferred from a dashboard or bounded ID match.
- Full VM backups remain waived; no unrelated VM or network changes.

## Review focus

- Alert copies must not satisfy native telemetry: test alert-only and wrong-parser input.
- Same provider does not identify Sysmon1: test Sysmon3 cannot satisfy A01.
- Wrong host/PID/tuple/rule/time must fail correlation without widening a window.
- Malformed aliases, multipart scripts and duplicate fields fail closed without leakage.
- Real replay retains exact bytes, EIDs and separate ancestor-linkage audit.

## Tasks

1. **Source contracts/profiles** — models `_canonical_fields.py`, `scenario.py`,
   validation/contracts.py; new SCN-005/006 and profiles. First add source-acceptance
   and source-isolation tests and observe failure. Add `elastic` without changing
   semantic sysmon→Wazuh contracts. Test profile fingerprints and negative bindings.
2. **Elastic connector** — `connectors/elastic/`, synthetic parser tests. APIs:
   `parse_elastic_sysmon1_document`, `parse_elastic_sysmon3_document`,
   `parse_elastic_powershell4104_document`, `parse_elastic_security_alert_document`
   accept bytes plus source_ref/environment_id/ingested_at and return event/provenance.
   Test strict errors, native precision, identities, flat alert keys and raw hashes
   before implementing; preserve optional nulls and source-specific provenance.
3. **Intake/package** — register the four keys with one closed ingested_at context;
   add the setuptools connector package. Test unknown/context errors, one parser
   per file, source ledger, wheel import and whole synthetic CLI report.
4. **Engine integration fixtures** — add clearly synthetic bundles for SCN-005/006,
   end-to-end tests for Detected, Missing telemetry, wrong host/PID/rule/time and
   missing-alert Inconclusive. Do not manufacture a complete-collection declaration.
5. **Checks/review** — run targeted red/green cycles, all backend checks, dependency
   and wheel build/install smoke; preserve command/UTC/exit logs. Independent review
   follows fixes; rerun checks affected by any fix. Record exact Git commit/patch.
6. **Private acceptance/handoff** — pin contracts before fresh safe live tests;
   reconcile native IDs, actual alert ancestors and network raw slices; assemble
   bundles outside Git, run CLI validate/replay, inspect report EIDs/raw hashes,
   package source/tests/native reports/limitations and verify every ZIP hash.

Execution follows the user's instruction to implement and verify in this chat;
human review/merge is the final repository step, after concrete code and evidence
exist. No automatic merge or false upstream-approval claim.

Verification ruling: the existing frontend lock pinned the dev-only transitive
`source-map-js` to vulnerable 1.2.1. A targeted update changes only that lock entry
to 1.2.2; no direct/runtime dependency is added. The initial npm audit and patched
zero-finding audit are preserved privately, and frontend tests/build are rerun.
Reference: [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q).
