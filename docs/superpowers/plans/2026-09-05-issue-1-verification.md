# Issue #1 verification and review handoff

Branch: feat/issue-1-canonical-event-schema, based on main at 5b686e4.
Environment: Windows, Python 3.13.14, Pydantic 2.13.5, pytest 9.1.1.

## Delivered contract

- CanonicalEvent schema version 1.0, four source enums and seven action enums.
- Explicit provenance with nullable source context and JSON round-trip support.
- UTC normalization, invalid-type/range checks, extra-field rejection.
- Exact-byte SHA-256 helper, without I/O or source parsing.
- Field documentation, runnable example, installable Python package.

## Verification actually run

- Initial tests failed at import because the package did not exist.
- Initial typed model: 21 failed / 65 passed; failures demonstrated missing UTC
  normalization and permissive timestamp/IP handling.
- Validators and hash helper: 94 passed.
- Additional boundary regressions: 7 failed / 96 passed, reproducing enum byte
  coercion, unordered technique inputs and UTC conversion overflow.
- After targeted fixes: `python -m pytest backend/tests -q` — 103 passed.
- `python -m pip check` — No broken requirements found.
- `python -m pip wheel --no-deps . --wheel-dir dist` — wheel built successfully.
- Installed that wheel with test dependencies into a new verification venv.
- Ran tests from build/ using that venv and --import-mode=importlib — 103 passed.
  Confirmed aegis_verify imported from the new venv's site-packages.
- Executed the Python example in docs/CANONICAL_EVENT.md — completed successfully;
  UTC output and unknown process_name matched the documentation.

The 103 count includes parametrized inputs, not 103 product features. No previous
product test suite existed at the branch baseline. Python 3.11/3.12 were not run.

## Issue acceptance mapping

| Criterion from previously retrieved Issue #1 | Evidence |
| --- | --- |
| Versioned schema and readable fields | canonical_event.py, docs/CANONICAL_EVENT.md |
| Validated and serializable examples | Full/minimal events and documented example |
| Optional null and invalid required field tests | test_canonical_event.py |
| Stable ID and mandatory raw reference | Required event_id/raw_event_ref; stability belongs to collectors |
| Vendor-neutral engine interface | CanonicalEvent contains normalized fields only; no engine built yet |
| Tests remain green | 103 passed, including installed-wheel verification |

## Limits and next step

The issue was not fetched again from GitHub during this session. Check any newer
issue edits before declaring it closed. No PR/issue state or scenario ground truth
was changed. No lab logs, connector behavior or detection claims were validated.

Model validation does not authenticate evidence, check that raw_event_ref exists,
or guarantee global uniqueness of caller-supplied event IDs. Tests use artificial
contract data; no INC-002 fixture is supplied or invented.

Human review should confirm the field contract before Issue #2 consumes it.
Keep this branch for review and do not merge automatically.
