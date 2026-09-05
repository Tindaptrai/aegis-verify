# Canonical Event Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. Execute sequentially with test-first checks; no independent agent work is needed.

**Goal:** Implement the approved Issue #1 data contract and exact-byte hashing.

**Architecture:** A pure event model with enums and a separate pure hashing helper;
source-specific parsing and result classification remain future consumers.

**Tech Stack:** Python >=3.11, Pydantic 2.13.5, pytest 9.1.1, setuptools, hashlib.

**Spec:** `docs/superpowers/specs/2026-09-05-canonical-event-design.md`.

## Global Constraints

- Implement only Issue #1; preserve scenarios and raw evidence.
- Unknown optional values are null and security conclusions are not inferred.
- Use artificial unit-test data labelled as such, not fabricated incident fixtures.
- Keep code on feat/issue-1-canonical-event-schema for human review.

## Task 1 — Required contract and serialization

Files: pyproject.toml, backend/app/__init__.py,
backend/app/models/__init__.py, backend/app/models/canonical_event.py,
backend/tests/test_canonical_event.py.

Produces CanonicalEvent, SourceType, EventAction, with the Pydantic interfaces
model_validate(data), model_validate_json(text), model_dump(mode="json"),
model_dump_json(), and model_json_schema().

- [x] Add tests for a minimal event and missing required values before the model.
- [x] Run the tests and confirm the missing-contract failure.
- [x] Implement required fields, optional context, enums and JSON round trip.
- [x] Run focused tests and record the actual outcome.

## Task 2 — Reject ambiguous or invalid records

Files: backend/tests/test_canonical_event.py and
backend/app/models/canonical_event.py.

- [x] Test naive/numeric/unknown-offset timestamps, wrong scalar types, invalid
  IP/port values, extra fields, invalid hashes and empty identifiers.
- [x] Run tests to prove these cases fail with the initial model.
- [x] Add the smallest validators for those boundaries and UTC normalization.
- [x] Rerun the contract tests including full-event serialization and immutability.

## Task 3 — Exact-record hash

Files: backend/tests/test_evidence.py and backend/app/evidence.py.
Produces hash_raw_event(raw_record: bytes) -> str, with no I/O or transformation.

- [x] Test literal SHA-256 vectors for empty bytes and b"abc", repeated calls,
  byte changes, newline sensitivity, and rejection of non-bytes input.
- [x] Run tests before creating the helper.
- [x] Implement hashlib.sha256(raw_record).hexdigest() with an explicit bytes check.
- [x] Run all tests and pip check.

## Task 4 — Documentation and review

Files: docs/CANONICAL_EVENT.md, README.md, backend/README.md.

- [x] Document every field, input rules, exact hash policy, model usage and limits.
- [x] Verify clean installation with python -m pip install -e ".[test]".
- [x] Run python -m pytest backend/tests -q and python -m pip check.
- [x] Run git diff --check and inspect the relevant changed files.
- [x] Record the real results and preserve the change for human review without merging.
