# CLI Validate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the offline `aegis validate` command for Issue #8, with explicit fixture bundles, safe diagnostics and evidence-linked text/JSON output.

**Architecture:** An intake boundary reads closed JSON contracts and exact-byte snapshots, then dispatches only existing connector APIs. The CLI selects one profile/context, calls the unchanged engine, and renders a versioned report. No source parsing or security verdict logic moves into the CLI.

**Tech Stack:** Python >=3.11, existing Pydantic/PyYAML/pytest, standard-library argparse/pathlib/json/hashlib; no new runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-09-11-cli-validate-design.md` (approved in chat).

## Global Constraints

- Only Issue #8; no live I/O, execution, UI, CSV or run comparison.
- Preserve CanonicalEventV2, EvaluationResult and all scenario ground truth.
- Explicit one-source selection, no fallback/merge/field overrides or inferred clocks/completeness.
- At most 100 files, 32 MiB/file, 64 MiB total evidence, 20,000 physical lines, 10,000 events.
- Config: 1 MiB, depth 32, 50,000 nodes, 128-character integer tokens, no float/duplicate keys/non-finite/surrogates.
- Encoded output <=32 MiB; no partial verdict on error.
- Text/JSON exits: success 0, missing telemetry/false negative 1, input error 2, inconclusive 3, internal/output error 4.
- Real logs stay private; synthetic test bundles are labeled test-only. No automatic push/merge.

## File map and shared interfaces

- `backend/app/intake/errors.py`: frozen diagnostic exception `IntakeError(code, *, stage="inputs", file_index=None, field=None, line=None)`; fixed hints and sanitized coordinates.
- `backend/app/intake/io.py`: `read_local(path, *, limit, stage) -> bytes`, `local_path(path, *, directory=False, stage="inputs") -> Path`, `bundle_path(root, relative) -> Path`, `decode_config(raw, *, stage) -> dict`.
- `backend/app/intake/contracts.py`: closed `BundleFile`/`BundleManifest` and parser context models; `parse_manifest(data) -> BundleManifest`.
- `backend/app/intake/registry.py`: `parse_entry(raw: bytes, entry: BundleFile, environment_id: str) -> tuple[tuple[CanonicalEventV2, ...], tuple[LedgerEntry, ...]]`; `LedgerEntry` frozen dataclass with source_ref, parser, source_type, line_start/end, raw_event_ref/hash, event_id (nullable), status, reason (nullable), warnings tuple.
- `backend/app/intake/loader.py`: `load_bundle(root: Path, manifest: BundleManifest) -> IntakeResult`; frozen IntakeResult with events tuple, ledger tuple, inventory tuple. Inventory dicts contain source_ref/path/parser/sha256/context_fingerprint. `check_collection(intake, profile, context) -> None` raises collection_conflict for unsupported skip vs same-source complete detection.
- `backend/app/intake/__init__.py`: public exports for above consumer interfaces.
- `backend/app/cli/service.py`: `evaluate_bundle(scenario, fixture, *, profile=None, context=None) -> dict` with complete report.
- `backend/app/cli/reporting.py`: `render_report(report, format) -> str`, bounded serialization, status->exit mapping.
- `backend/app/cli/__init__.py`: `main(argv=None) -> int`; uses sys.stdout/stderr, safe argparse/help/error behavior.
- `backend/app/__main__.py` plus `pyproject.toml`: module/console entry points, package lists.
- Tests split into `test_intake_io.py`, `test_intake_bundle.py`, `test_cli_validate.py`, `test_cli_acceptance.py`.
- User guide `docs/CLI_VALIDATE.md`; synthetic portable example `tests/fixtures/cli/synthetic-detected/` and scenario under that test directory, not production scenarios.

## Task 1 — Safe configuration and filesystem boundary

Own errors.py/io.py, test_intake_io.py and package scaffold. Reviewable independently of connector integration.

- [x] Write red tests. Imports stay inside tests until modules exist so absence is an assertion-phase failure. Actual cases include:

```python
def test_duplicate_keys_never_select_last_value():
    from aegis_verify.intake.io import decode_config
    from aegis_verify.intake.errors import IntakeError
    with pytest.raises(IntakeError) as caught:
        decode_config(b'{"files":[],"files":["private-value"]}', stage="inputs")
    assert caught.value.code == "invalid_json"
    assert "private-value" not in str(caught.value)

def test_bundle_path_cannot_leave_root(tmp_path):
    from aegis_verify.intake.io import bundle_path
    from aegis_verify.intake.errors import IntakeError
    with pytest.raises(IntakeError):
        bundle_path(tmp_path, "../outside.json")
```

- [x] Run `.venv/Scripts/python.exe -m pytest backend/tests/test_intake_io.py -q -p no:cacheprovider --basetemp build/task1-red`; verify missing boundary failures.
- [x] Implement closed diagnostics, bounded read with file identity/stat regular/reparse checks, path validation before opens, bounded JSON structural walk and strict decoder hooks. Use a resolved Path for opens; check each ancestor without following reparse points. Reject DOS device basenames including extensions/superscript device digits, UNC/device/ADS, glob/control/trailing dot/space path components.

```python
def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntakeError("invalid_json")
        result[key] = value
    return result
```

- [x] Expand red/green cases for byte/depth/node/int limits, BOM, null/non-object, floats, unknown coordinates, traversal, Unicode/spaces, links/hardlinks/FIFO where platform permits, unreadable/missing files. Use tmp_path, no user files.
- [x] Run targeted tests and full suite with a fresh basetemp. Commit `feat(intake): add safe local configuration boundary`.

## Task 2 — Typed bundle and existing parser integration

Own contracts.py/registry.py/loader.py and test_intake_bundle.py. Consumes Task 1 interfaces. Public outputs are as defined in file map; do not edit engine/connectors.

- [x] Write red tests for manifests, six parser dispatches, exact-byte hash, ledger and atomic failure. Use existing sanitized fixture bytes, copy into tmp_path and build explicit entries.

```python
def test_empty_bundle_does_not_fabricate_events(tmp_path):
    from aegis_verify.intake.contracts import parse_manifest
    from aegis_verify.intake.loader import load_bundle
    manifest = parse_manifest({"bundle_schema_version":"0.1.0",
                              "environment_id":"synthetic-env", "files":[]})
    result = load_bundle(tmp_path, manifest)
    assert result.events == ()
    assert result.ledger == ()
```

- [x] Run targeted tests red; implement Pydantic context models with exact allowed fields per registry key; frozen metadata. Each source result is converted to ledger without reading vendor fields outside connector outputs.

```python
raw = read_local(path, limit=file_limit, stage="evidence")
if sha256(raw).hexdigest() != entry.sha256:
    raise IntakeError("hash_mismatch", stage="evidence", file_index=index)
events, ledger = parse_entry(raw, entry, manifest.environment_id)
```

- [x] Validate inventory physical identities and unique refs before parsing; count raw bytes/physical lines including skips, stop before engine on limits. Do not prefilter events. Translate source exceptions to allowlisted codes/coordinates, preserving no raw values. Collection policy compares registry canonical source type to supported detection declarations.
- [x] Add boundary tests, late malformed input/no returned IntakeResult, unknown parser/no fallback, stale/unsupported complete declaration, skipped IDs never promoted to canonical events, parser warnings and physical evidence coordinates.
- [x] Run targeted plus full tests. Commit `feat(intake): assemble explicit fixture bundles`.

## Task 3 — Evaluation service and CLI contracts

Own cli package, __main__.py, pyproject packaging edits, test_cli_validate.py. Consumes Task 1/2 and existing engine public API.

- [x] Write red subprocess tests (`sys.executable -m aegis_verify`) for help, missing/duplicate/unknown flags, text/JSON selection. Write service tests with actual synthetic files parsed by real connectors; no mocked final verdict.

```python
def test_missing_required_input_is_safe_error():
    result = subprocess.run([sys.executable, "-m", "aegis_verify", "validate"],
                            capture_output=True, text=True)
    assert result.returncode == 2
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
```

- [x] Implement exact selection (explicit profile/context skips default entirely); bounded raw config hashes; typed scenario/profile/context; environment equality; intake->collection check->evaluate_scenario once. Never patch mismatching fingerprints or context.
- [x] Report shape: cli_report_version/kind/scenario/evaluation/intake/counts/input_fingerprints. Preserve EvaluationResult via model_dump(mode="json"); count referenced via evidence_index. Keep inventories/ledger sanitized; text emits proof/unevaluable IDs separately and warnings/assurance.
- [x] Implement argparse with allow_abbrev=False, reject duplicates, safe usage errors without argv values, no @file expansion. Help returns 0; errors stderr; JSON mode determined only by unambiguous explicit --format json. Bounded iterencode before stdout, then write+flush with output-error handling.
- [x] Test default and external file selection/no fallback, all 5 statuses and errors, malicious names/control chars, output resource boundary, broken pipe/internal errors, stdout JSON parseability/determinism.
- [x] Update package registration and console script `aegis = "aegis_verify.cli:main"`; install editable and test module/console parity. Commit `feat(cli): expose offline evidence validation command`.

## Task 4 — Acceptance, portable example, documentation and release verification

Own test_cli_acceptance.py, tests/fixtures/cli/synthetic-detected, docs/CLI_VALIDATE.md and focused README CLI status section.

- [x] Create synthetic-only input bundle + test-only scenario with telemetry and detection from two real parser-compatible input records; no credentials, realistic secret samples or lab verdict claims. Profile literal IDs and target labels are synthetic. Compute and review hashes explicitly for test fixtures; no production fixture generator.
- [x] Run actual command against this bundle red before finalizing acceptance expectations; expected status Detected, two distinct IDs/witness pair. Negative variants remove alert or use unknown context, malformed last input, missing profile. Add Prevented fixture case via existing source parser and blocked witness; every acceptance path uses real engine.
- [x] Write guide in Vietnamese for new venv, sample command, input schema/context per source, file selection, every exit code, report privacy, skips/assurance, unsupported scenario gaps and safe output destination.
- [x] Full test command: `.venv/Scripts/python.exe -m pytest backend/tests -q -p no:cacheprovider --basetemp build/issue8-final-<unique>` (create build directory first; each run uses a fresh name).
- [x] Run pip check and git diff --check. Build wheel via `pip wheel . --no-deps --wheel-dir build/issue8-wheel`, install into separate venv, invoke module and console from outside checkout against the portable bundle, verify package __file__ is site-packages.
- [x] Request independent reviewer against approved spec/full diff; fix findings with regression tests and re-review. Record verified counts and remaining limitations in guide/handoff; commit only scoped files.
- [x] Stop for user local validation. Do not push, create PR, merge, delete worktree, or start Issue #9 without authorization.

## Plan self-review

Spec sections 2/3 -> Tasks 1/3; registry/pipeline/skips -> Task 2; output/exit/privacy -> Task 3; packaging/acceptance/human handoff -> Task 4. Exact shared interfaces are in the file map. No need to change existing ground truth or engine contracts.

## Execution record

- Spec approved; isolated worktree already exists at the Issue #8 branch.
- Baseline from design preparation: 1631 passed, dependency check clean.
- Tasks 1–3 implemented and independently reviewed: boundary mutation protection,
  exact resource-limit tests, and real-process stdout/stderr shutdown handling were
  corrected and re-reviewed. Latest production commit: `1fd56a9`.
- Task 4 implemented at `a284a3e`, with precise stale-attestation regression
  assertions at `98f43b9`; scoped review and re-review are clean. Whole-branch
  review and final controller verification are complete. Human validation remains
  pending; no push, PR, merge, or Issue #9 authorization.
- Packaging registration for intake was moved forward into Task 1 to expose the
  package to editable-install tests; this changed sequencing only, not dependencies.
- Controller reran the portable example: `Detected`, exit 0, two referenced IDs.
  Independent Python 3.12.1 wheel consumer imported from site-packages and produced
  equal module/console JSON and text; its dependency check passed.
- Final review found malformed parser arrays/objects escaping input validation,
  a Windows-only console filename in the parity test, and a trailing slash in the
  README example. The unified fix at `853887f` adds nine regressions; scoped
  re-review confirmed all three addressed with no new breakage or deferred findings.
- Controller verification of the final code: **1781 passed, 1 skipped in 26.71s**
  (FIFO unavailable on Windows), `pip check` and whole-branch `git diff --check`
  clean. Production scenarios, connectors, canonical models and engine unchanged.
- Rebuilt final wheel: `build/issue8-wheel-final-853887f/aegis_verify-0.1.0-py3-none-any.whl`,
  SHA-256 `fd5935a832cd803fdd2a473da1752863fbee66dfebbbe652a283890163e99efa`.
  Reinstalled in the isolated Python 3.12.1 consumer outside checkout; verified
  site-packages import, identical module/console JSON and text, dependency check,
  and safe rejection of both invalid parser container types in the installed code.
- Python 3.11, POSIX execution, and actual lab validation remain unverified.
  Synthetic witnesses validate the offline software path, not operational coverage.
- Implementation handoff is complete locally. Preserve the branch/worktree for
  human checks; push/PR/merge and Issue #9 remain separately authorized actions.
