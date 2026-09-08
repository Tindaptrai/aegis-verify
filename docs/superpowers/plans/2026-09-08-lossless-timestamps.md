# Lossless Timestamps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for the inline execution requested in this conversation. Steps use checkbox syntax.

**Goal:** Implement Issue #15, exact nanosecond timestamps alongside unchanged v1 behavior.

**Architecture:** PreciseTimestamp owns exact UTC values and Pydantic integration. V1/V2 share non-time validation; a bounded, versioned reader and explicit migration sit outside the models.

**Tech Stack:** Python >=3.11, Pydantic 2.13.5, standard library; existing pytest, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-08-lossless-timestamps-design.md`, approved by the user before this plan.

## Global Constraints

- Preserve CanonicalEvent v1 API, default schema_version 1.0 and existing tests.
- Add CanonicalEventV2, schema_version 2.0, exact timestamp and ingested_at.
- ASCII RFC3339 with known offset, 0..9 fractional digits, years 0001..9999 UTC.
- No float arithmetic, implicit downgrade, timestamp guessing or evidence rewriting.
- Reader: 1 MiB wire input, container depth 32, numeric token 128 characters.
- Source parsing, CSV, live connectors, scenario ground truth are out of scope.
- Public errors must not echo input; no secrets/real log fixture in this change.
- Run tests with this worktree's own `.venv/Scripts/python.exe`; use fresh basetemp paths under ignored build/ for full-suite runs.
- Human review before push/merge; user requested implementation and testing, not merge.

## Task 1 — Exact value object

**Files:** create backend/app/models/precise_timestamp.py and backend/tests/test_precise_timestamp.py.

**Interface:** PreciseTimestamp.parse(str | datetime | PreciseTimestamp), isoformat(), epoch_nanoseconds, nanosecond, fractional_digits, difference_ns(other), to_datetime_exact(), same-instant equality/hash and ordering.

- [x] Write tests with literal expected timestamps for 0..9 precision, equivalent offsets, 1 ns differences, epoch -1, calendar/range errors, Unicode digits, exact datetime conversion and invalid value construction.

```python
def test_one_nanosecond_is_not_lost():
    from aegis_verify.models.precise_timestamp import PreciseTimestamp
    a = PreciseTimestamp.parse("1970-01-01T00:00:00.000000001Z")
    assert a.epoch_nanoseconds == 1
    assert a.isoformat() == "1970-01-01T00:00:00.000000001Z"
    with pytest.raises(ValueError):
        a.to_datetime_exact()
```

- [x] Run `python -m pytest backend/tests/test_precise_timestamp.py -q`; observe missing feature before production code.
- [x] Implement immutable slotted object with guarded component creation, integer calendar conversion and UTC serializer. Core arithmetic:

```python
delta = utc_whole_second - datetime(1970, 1, 1, tzinfo=timezone.utc)
seconds = delta.days * 86400 + delta.seconds
nanoseconds = int(fraction.ljust(9, "0")) if fraction else 0
epoch_ns = seconds * 1_000_000_000 + nanoseconds
```

  Validate ASCII syntax and calendar before this arithmetic. Subtract text timezone offset from the whole second only; never parse the fractional tail through datetime. Store fractional width separately; equality/hash uses seconds+nanos, not width.
- [x] Integrate Pydantic plain validation with explicit string JSON schema and a JSON-only serializer; test via TypeAdapter and later v2.
- [x] Run exact-time tests; refactor only after green; commit exact value and tests.

## Task 2 — Shared canonical contracts, v2 and regression

**Files:** create models/_canonical_fields.py and models/canonical_event_v2.py; modify models/canonical_event.py and models/__init__.py; add backend/tests/test_canonical_event_v2.py.

**Interface:** unchanged CanonicalEvent/EventAction/SourceType, new CanonicalEventV2 and PreciseTimestamp exports.

- [x] Write failing integration tests for v2 before creating the model:

```python
def test_v2_json_keeps_nanos(event_data):
    from aegis_verify.models import CanonicalEventV2
    event = CanonicalEventV2.model_validate(event_data | {
        "timestamp": "2026-01-01T00:00:00.123456789Z",
    })
    wire = event.model_dump_json()
    assert json.loads(wire)["timestamp"] == "2026-01-01T00:00:00.123456789Z"
    assert CanonicalEventV2.model_validate_json(wire).timestamp.nanosecond == 123456789
```

  event_data uses artificial mandatory provenance, as the v1 tests do. Cover both timestamp fields, dict/JSON routes, required/null/extra/enum/IP/ports/Unicode errors, Python dump preserving object, JSON Schema pattern, v1 rejecting v2 and v2 rejecting v1.
- [x] Run `python -m pytest backend/tests/test_canonical_event_v2.py -q` and observe missing model.
- [x] Extract existing non-time fields and validators without changing semantics into CanonicalFields; leave time validators only on v1. Define v2:

```python
class CanonicalEventV2(CanonicalFields):
    schema_version: Literal["2.0"] = "2.0"
    timestamp: PreciseTimestamp
    ingested_at: PreciseTimestamp
```

- [x] Export the new model without changing the CanonicalEvent alias. Run both canonical test modules and exact-time tests; then full baseline suite with fresh basetemp.
- [x] Commit shared fields/v2/tests after all checks pass.

## Task 3 — Versioned reader and explicit migration

**Files:** create backend/app/canonical_io.py, optional private backend/app/_canonical_json.py for bounded JSON policy, and backend/tests/test_canonical_io.py.

**Interface:** parse_canonical_event(dict), parse_canonical_event_json(str|bytes), upgrade_canonical_event(CanonicalEvent), CanonicalReadError with fixed code/allowlisted field_path.

- [x] Write failing tests for explicit version dispatch and migration:

```python
def test_dispatch_does_not_upgrade(event_data):
    from aegis_verify.canonical_io import parse_canonical_event, upgrade_canonical_event
    old = parse_canonical_event(event_data | {"schema_version": "1.0"})
    assert type(old) is CanonicalEvent
    upgraded = upgrade_canonical_event(old)
    assert upgraded.schema_version == "2.0"
    assert upgraded.raw_event_hash == old.raw_event_hash
    assert old.schema_version == "1.0"
```

  Add missing/null/unknown version, duplicate keys, malformed UTF-8, deep/oversized data, numeric limits/nonfinite, surrogate keys/values, dict cycles, no input mutation and secret marker in diagnostics. Revalidate forged v1 model_copy/model_construct before migration.
- [x] Run reader tests and observe missing APIs before implementation.
- [x] Implement byte/character guards and lexical depth preflight; strict json.loads hooks for duplicate keys and numeric tokens. Walk JSON-like tree with active-path cycle detection, UTF-8/finite/type validation. Dict callers may share subtrees but may not create cycles.
- [x] Dispatch using a constant version map, never timestamp heuristics:

```python
model = {"1.0": CanonicalEvent, "2.0": CanonicalEventV2}.get(version)
if model is None:
    raise CanonicalReadError("unsupported_version")
return model.model_validate(data)
```

  Check version is a string before lookup. Catch only expected parse/validation exceptions; translate public error without input/context/unknown keys. Fixed diagnostic paths must come from canonical field names, not source keys.
- [x] Upgrade by revalidating v1 data, serializing its validated JSON-mode representation, replacing schema_version and validating v2; do not write files. Catch serializer failures into sanitized public error.
- [x] Run reader tests, full backend suite and pip check; commit after green.

## Task 4 — Documentation, packaging and review

**Files:** docs/CANONICAL_EVENT_V2.md, docs/CANONICAL_EVENT.md, README.md if a link is needed, docs/superpowers/plans/2026-09-08-issue-15-verification.md.

- [x] Document wire format, Python API break isolated to v2, precision-width vs clock accuracy, explicit version reader, migration limitations, exact-only datetime conversion and bounded-reader errors.
- [x] Run documented example using artificial data against editable installation; verify no float/nanosecond loss.
- [x] Build wheel: `python -m pip wheel . --no-deps --wheel-dir dist`; install into a fresh ignored build/package-check venv and run tests from build/ using `--import-mode=importlib` so imports resolve to site-packages, not the editable checkout.
- [x] Run `pip check` in both environments; `git diff --check`; compare scenarios/connectors/evidence helper to main and inspect staged diff for scope and secrets.
- [x] Request code review; address findings via reproducing tests, then rerun checks. Preserve user files and branches. Record exact verification output, test counts and known platform limits.
- [x] Final handoff with worktree, commit, runnable test commands and explicit no-push/no-merge status.

## Completion notes

- Implemented and tested inline on the isolated Issue #15 worktree; no push/merge.
- Revalidation reads the v1 field dictionary before serializers run, preserving
  unknown keys for extra-forbid detection and avoiding serializer calls on forged values.
- Immutable slots replaced the initial dataclass attempt because Python-mode
  serialization otherwise exposed component dictionaries. Copy/deepcopy are supported.
- Dict input gets an expanded compact UTF-8 JSON size budget, including repeated
  subtrees; model-to-model migration intentionally does not inherit reader budgets.
- Final independent review's P2 migration finding was reproduced, fixed and reviewed again.
- Full editable and installed-wheel suites: 507 passed each; both pip checks clean.
- Human review/approval and future Wazuh lab validation remain pending, not checked off here.
- Detailed commands and limits: [verification report](2026-09-08-issue-15-verification.md).
