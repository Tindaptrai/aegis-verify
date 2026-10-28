# Bounded Collection Set Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox syntax for tracking.

**Goal:** Collect bounded overflow windows and evaluate their complete canonical set once for issue 161.

**Architecture:** Reuse adaptive Wazuh collection, add atomic shared-budget bundle intake, then integrate a set evaluator in Manager. Preserve single-bundle behavior and immutable failed evidence.

**Tech Stack:** Existing Python, pytest, Django; no new dependency.

**Spec:** `docs/superpowers/specs/2026-10-28-bounded-collection-set-design.md`

## Global Constraints

- Only issue 161; no scenario ground-truth edits, authority expansion or production credentials.
- At most 100 records per leaf, 63 attempts, 32 leaves, shared 16 MiB responses and 600 seconds.
- Retain intake limits and engine's global event/comparison limits.
- Unknown assurance and per-collection snapshots remain explicit.

## Review Focus

- Duplicate source IDs across leaves fail rather than being hidden by namespacing (task 1).
- Failed parents consume the shared budget and failed cleanup cannot split (task 1).
- Cross-leaf joins evaluate once; missing alerts do not gain completeness (tasks 2/3).
- Empty leaves, gaps/overlap, changed hashes and physical aliases fail safely (task 2).
- Existing output and failed jobs are never reused or reset (task 3).

### Task 1: Bounded adaptive collector

**Files:** `connectors/wazuh/live.py`, `backend/tests/test_wazuh_adaptive.py`.

**Interfaces:** `collect(..., source_ref_prefix="")`; `collect_adaptive(..., namespace_sources=False)`. Manager passes `namespace_sources=True`. Namespace uses attempt directory plus hyphen. Successful batch and collection metadata include `environment_id` and leaf `inputs_sha256` (null for empty leaf). Shared native identity checks and budgets live inside collector.

- [ ] Write and run failing tests for namespaced canonical refs, sibling duplicate native IDs, shared byte/deadline limits and 174 synthetic records without truncation.
- [ ] Implement bounded collection while preserving old default source refs and single API.
- [ ] Run live/adaptive tests and request independent task review.

### Task 2: Shared intake and one set evaluation

**Files:** `backend/app/intake/loader.py`, `backend/app/intake/__init__.py`, `backend/app/cli/service.py`, new `connectors/wazuh/batch.py`, and focused backend tests.

**Interfaces:** `load_bundle_set(root, members)` where members is a tuple of `(relative_leaf_directory, BundleManifest)`; returns `IntakeResult`. `evaluate_collection_set(scenario, fixture, *, profile=None, context=None)` reads and verifies batch and ordered leaves through `connectors.wazuh.batch`, loads all canonical evidence and produces the ordinary report with a collection-set input fingerprint. Existing `evaluate_bundle` report remains compatible.

- [ ] Write/run failing tests for global limits/uniqueness and combined cross-leaf witness.
- [ ] Add shared loader accumulator and validate bounded metadata/coverage/hash/count/cleanup/empty leaves without vendor parsing in engine.
- [ ] Share report construction and evaluate once; bind input fingerprints to batch and leaf manifests.
- [ ] Run intake/service/set tests and request independent task review.

### Task 3: Manager integration and verification

**Files:** `manager/control/collection.py`, `manager/control/tests/test_collection.py`, related execution collection tests; `scripts/run_required_manager_tests.py` and its fixture tests for Python skip-count compatibility.

- [ ] Write/run failing Manager regression for 174 synthetic records and failure preservation.
- [ ] Call `collect_adaptive(namespace_sources=True)` and `evaluate_collection_set`; preserve pins/declarations/unknown assurance. Add per-collection snapshot limitation to metadata.
- [ ] Run focused core and Manager suites; review complete change and run required CI before deployment claim.
- [ ] Reproduce decorated required-skip and optional-skip count failure; count recorded skips without treating them as started executions. Verify required skips still fail and setup errors cannot manufacture executions.
- [ ] Prepare Manager-only guarded upgrade/recovery instructions after review; update WSGI and worker runtime together. Native retry requires a fresh owner-approved preview/job.
