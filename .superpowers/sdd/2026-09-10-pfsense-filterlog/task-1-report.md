# Task 1 report — explicit context and safe model boundary

Date: 2026-09-10

## Scope completed

Implemented only the Task 1 boundary for the offline pfSense filterlog connector:

- a frozen, extra-forbid `PfSenseContext`;
- `make_context(...)` with strict caller validation and safe errors;
- `source_timestamp(...)` with a fixed English month table, calendar validation,
  explicit source year/offset, UTC conversion through `PreciseTimestamp`, and
  second precision;
- allowlisted `PfSenseParseError`/`PfSenseDiagnostic`;
- frozen, extra-forbid `PfSenseProvenance` and `PfSenseRecord`;
- parsed/skipped outcome invariants and evidence identity matching;
- the pfSense package export surface and setuptools package entry;
- focused tests for valid/invalid context, time boundaries, safe errors,
  null optional metadata, immutability, extra rejection, and outcome invariants.

No filterlog framing, header parsing, field mapping, bytes/file API, fixture,
scenario ground truth, live dependency, or connector I/O was implemented.

## Public interfaces

`aegis_verify.connectors.pfsense` exports:

```python
make_context(
    *,
    source_ref,
    environment_id,
    sensor_id,
    ingested_at,
    source_year,
    source_utc_offset,
) -> PfSenseContext

source_timestamp(text: str, context: PfSenseContext) -> PreciseTimestamp

PfSenseContext
PfSenseDiagnostic
PfSenseParseError
PfSenseProvenance
PfSenseRecord
```

`PfSenseParseError` exposes both `.diagnostic` and direct safe properties
`.code`, `.field_path`, `.line`, and `.record_index`. Unknown codes become
`invalid_field`; unknown field paths become `None`; invalid line/index values
cannot enter the diagnostic.

`PfSenseProvenance` has these exact fields for later parser/mapping work:

```text
mapping_version, input_profile, timestamp_basis, source_ref, sensor_id,
record_index, line_start, line_end, event_id, raw_event_hash, raw_event_ref,
interface, direction, reason, rule_number, subrule, anchor, tracker,
protocol_id, protocol_text, timestamp_text, source_year, source_utc_offset,
nat_context, warnings
```

The literals are:

- `mapping_version="pfsense-filterlog-v1"`
- `input_profile="pfsense-filterlog-bsd-ipv4-tcp-udp-v1"`
- parsed `timestamp_basis="bsd_syslog_with_caller_context"`
- warning `year_and_offset_supplied_by_caller`

Optional vendor metadata defaults to `None`. `nat_context` is intentionally
None-only. Valid skip reasons are `blank_line`, `rotation_notice`,
`unsupported_ip_version`, and `unsupported_protocol`.

## TDD evidence

Dedicated environment setup:

```text
I:/AEGIS-VERIFY/.worktrees/issue-4-suricata-direct-eve/.venv/Scripts/python.exe -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[test]"
.venv/Scripts/python.exe -c "import aegis_verify; print(aegis_verify.__file__)"
```

The import resolved to this worktree:

```text
I:\AEGIS-VERIFY\.worktrees\issue-5-pfsense-fixture-parser\backend\app\__init__.py
```

RED command:

```text
.venv/Scripts/python.exe -m pytest backend/tests/test_pfsense_context.py -q
```

Expected failure:

```text
ImportError: cannot import name 'PfSenseContext' from
'aegis_verify.connectors.pfsense'
1 error during collection
```

First GREEN attempt found one independently hand-derived test typo:
`2024-01-01T00:00:00+07:00` was incorrectly expected in UTC year 2025.
The observed value correctly used UTC year 2023, so the literal expectation was
corrected without changing production code.

Focused GREEN command/result:

```text
.venv/Scripts/python.exe -m pytest backend/tests/test_pfsense_context.py -q
48 passed in 0.21s
```

The tests use real Pydantic/Canonical Event/PreciseTimestamp behavior with no
mocks. Mutation checks covered removal of strict year/offset validation,
machine-time/locale timestamp substitution, UTC overflow normalization, input
echoing, invented optional metadata, missing outcome checks, and mismatched
event/provenance ID/hash/reference.

## Verification evidence

Full suite, using a unique newly created basetemp and no pytest cache provider:

```text
.venv/Scripts/python.exe -m pytest -q --basetemp <fresh-build-dir> -p no:cacheprovider
975 passed in 3.17s
```

The exact basetemp was
`build/pytest-task1-1f6f0ac6e170402db2721497d6867d1e`.

Dependency verification:

```text
.venv/Scripts/python.exe -m pip check
No broken requirements found.
```

Wheel verification:

```text
.venv/Scripts/python.exe -m pip wheel . --no-deps --wheel-dir <fresh-dir>
Successfully built aegis-verify
```

The resulting wheel was installed into a fresh venv. Import resolved from that
venv's `site-packages/aegis_verify/connectors/pfsense/__init__.py`, and a
`make_context(...)` smoke check returned `source_year == 2026`.

## Handoff notes

- `source_timestamp` lives in `_context.py` as ruled.
- The package entry was moved forward from Task 3 only to make installed imports
  include `aegis_verify.connectors.pfsense`.
- `ingested_at` is validated/normalized to `PreciseTimestamp`; caller labels,
  environment text, source year, and offset are otherwise preserved unchanged.
- The controller's separate unstaged design-spec adjustment was preserved and
  is not part of the Task 1 commit.
- No substantive unknown remains in this task. Human review and later lab
  validation remain required before merge under `AGENTS.md`.
