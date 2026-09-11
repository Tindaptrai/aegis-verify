# Validation Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement approved Issue #7 direction A as an offline, evidence-linked validation library.
**Architecture:** Strict sidecar EvaluationProfile + unchanged ScenarioManifest + CanonicalEventV2 + explicit EvaluationContext enter a pure evaluator. Three-valued predicates and same-pair temporal joins produce immutable, deterministic assertion results and five scenario statuses. B remains a future adapter.
**Tech Stack:** Python >=3.11, existing Pydantic 2.13.5, pytest 9.1.1, standard-library hashing/IP handling; no new runtime dependencies.
**Spec:** docs/superpowers/specs/2026-09-11-validation-engine-design.md (approved 2026-09-11).

## Global Constraints

- Implement only Issue #7. Do not modify scenario ground truth, canonical schemas, connectors, or raw evidence.
- Public evaluation accepts typed contracts and finite list/tuple CanonicalEventV2 events only; revalidate constructed/copied models. No network, file access, live collection, UI, CLI, vendor/provenance reads or inferred fields.
- Predicates: all-of eq/in/exists/contains; contains is exact technique_ids membership only. False dominates unknown. Null is unknown except exists(null) is false. Text is exact/case-sensitive; IP compares semantic address values.
- Supported scope requires explicit source_type and target eq/in binding. Sysmon/PowerShell require Wazuh plus explicit provider equality. Detection needs reviewed rule/signature eq/in; prevention needs event_action eq blocked. Targets anchor exactly one supported telemetry root; no self-pair, chains, NAT/session inference.
- Time is exact nanoseconds within closed evaluation window. Missing detection becomes false_negative only with satisfied activity, no potential unknown witness, every anchor correlation interval covered, and valid caller-attested complete collection bound to profile/scope/event-set fingerprints.
- Assertion precedence is inconclusive > missing_telemetry > false_negative > success. Evaluate every assertion; preserve outcomes/counts and evidence IDs. Result is immutable and stable under event input permutation; duplicate event IDs reject the entire input.
- Limits: 10000 events, 100 assertions, 16 scope and 16 match conditions per rule, 100 in values, 8 join pairs, 100 bindings, 1000000 candidate/pair comparisons, 4096 UTF-8 bytes per literal/text/binding value. Exceeding limits is an atomic resource_limit error.
- Errors expose only stable code and safe field path/index, not input values, arbitrary keys, commands, usernames or exception locals. No production synthetic log generation.
- Tests first with observed RED then GREEN; use literal independently derived expectations. Human review/lab comparison precedes any merge. Do not push or merge in this plan.

## File map and interfaces

- `backend/app/validation/contracts.py`: frozen profile/context models and structural invariants. `Predicate(field, op, value=None, values=None, binding=None)`, `Binding(name, value)`, `JoinPair(target_field, anchor_field)`, `Correlation(anchor_assertion_id, join_pairs, min_delta_ns, max_delta_ns)`, `AssertionRule(assertion_id, role, capability, reason_code=None, source_type=None, scope=(), match=(), correlation=None)`, `EvaluationProfile`, `CollectionDeclaration`, `EvaluationContext`.
- `backend/app/validation/errors.py`: `ValidationEngineError(code, path)` with safe diagnostics.
- `backend/app/validation/predicates.py`: field types/allowlists, binding resolution, `Truth`, `evaluate_conditions(event, conditions, bindings)` and typed joins.
- `backend/app/validation/results.py`: frozen `WitnessPair`, `AssertionResult`, `EvidenceEntry`, `OutcomeCounts`, `EvaluationResult`; `fingerprint`, `scenario_fingerprint`, `profile_fingerprint`, `scope_fingerprint`, `event_set_fingerprint`, `aggregate_status`.
- `backend/app/validation/_inputs.py`: public-boundary revalidation, cross-contract binding and completeness attestation validation; no source-specific logic.
- `backend/app/validation/engine.py`: bounded candidate selection, existential witnesses, temporal joins, status rules and evidence indexing. Public `evaluate_scenario(manifest, events, *, profile, context)`.
- `backend/app/validation/__init__.py`: deliberate public exports. `pyproject.toml`: register package only.
- `backend/tests/test_validation_*.py`: synthetic contract/predicate/engine/adversarial/integration tests. Shared clearly synthetic builders may live in `backend/tests/validation_cases.py`.
- `docs/VALIDATION_ENGINE.md`: versioned API, semantics, limits, safe examples and handoff. No real scenario profiles.

## Verification commands

Run from `I:/AEGIS-VERIFY/.worktrees/issue-7-validation-engine` using its own editable-install venv. `build` already exists. Each test invocation uses a unique basetemp.

```powershell
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q -p no:cacheprovider --basetemp ('build/pytest-issue7-' + [guid]::NewGuid().ToString('N'))
& '.\.venv\Scripts\python.exe' -m pip check
```

Baseline before feature: 1440 tests passed, pip check clean. Use focused filenames while iterating, full suite at task checkpoint. Commit only owned files with specific pathspecs.

### Task 1: Typed contracts, predicates and deterministic result primitives

**Own:** contracts.py, errors.py, predicates.py, results.py, initial __init__.py, package registration; test_validation_contracts.py, test_validation_predicates.py, test_validation_results.py and synthetic shared builders. Do not implement evaluator yet.
**Read:** AGENTS.md, docs/PRD.md, docs/ARCHITECTURE.md, approved spec sections 2–7, existing scenario.py, canonical_event_v2.py, _canonical_fields.py, precise_timestamp.py.
**Produce:** models/helpers in file map; downstream evaluator imports these, not private connector functions.

- [ ] Write failing contract tests for strictness, unknown fields, immutable nested tuples, model limits, unsupported/support invariants, temporal range, source/role obligations and exact predicate/binding types. Observe failures before implementing.
- [ ] Implement smallest contracts. Profile/result schema versions `0.1.0`, engine semantics `0.1.0`. CollectionDeclaration has assertion_id, status unknown|complete_for_scope, confirmed_by, reference, coverage_start/end, no_sampling_or_truncation, no_parse_errors_or_gaps, clocks_adequate and profile/scope/event-set fingerprint fields. Complete requires all confirmations true and all metadata; unknown cannot claim complete assurance. Context uses tuple bindings/declarations with unique keys, start/end/run/environment. Reject arbitrary iterables. Keep nested values immutable.
- [ ] Add RED predicate truth table tests, then implement typed literals and binding values (strict str/int or tuple of those for in; no bool/float/null literal). Field-dependent checks validate enum/IP/port/nonnegative integer domains. Prevent alternative operand combinations: exists has none, eq/contains exactly one literal or binding, in exactly one list or binding. Bindings resolve explicitly, missing binding errors. At most 4096 bytes per text value. Rule target-binding presence and logical-source mapping are checkable without guessing values.
- [ ] Add RED tests for exact text, equivalent IPv6, unused null, false+unknown, contains membership, joins same type, no prohibited join keys, enum/numeric string errors, all bounds at and above limit. Implement helpers.
- [ ] Add RED tests for fingerprints, frozen result serialization, all outcome precedence combinations and evidence ID ordering. Implement standard SHA256 compact sorted-key JSON preserving defaults/null and timestamp fractional width. Event set sort by event_id. Scope fingerprint excludes declarations, full context includes them. Fingerprint helpers must reject invalid typed models, not silently trust model_construct/model_copy; reusable boundary helper can be factored into _inputs.py later if needed but no circular imports.
- [ ] Results carry metadata described in spec, tuple evidence index entries sorted by event_id, counts, stable exact final status labels `Detected`, `Prevented`, `Missing telemetry`, `False negative`, `Inconclusive`. Assertion collection_reference plus collection_assurance (`caller-attested` only for validated complete; otherwise `unknown`) avoid implying engine verified collection.
- [ ] Run focused tests and full regression, self-review, commit `feat(validation): add typed evaluation contracts and predicate primitives`. Report exact exported interfaces and RED/GREEN evidence for downstream task/reviewer.

Example independently derived predicate assertions (adapt builder signatures to implemented models):

```python
assert evaluate_conditions(event_with_null_rule, (Predicate(field="rule_id", op="eq", value="reviewed-rule"),), {}) is Truth.UNKNOWN
assert evaluate_conditions(event_with_null_rule, (Predicate(field="rule_id", op="exists"),), {}) is Truth.FALSE
```

### Task 2: Revalidated bounded engine and all five outcomes

**Own:** _inputs.py, engine.py, public __init__.py, test_validation_engine.py, test_validation_boundaries.py; extend previous files only when required to satisfy approved contract and cover with regression tests.
**Read:** AGENTS.md, PRD/ARCHITECTURE, approved spec all sections; Task 1 interfaces/report, not the whole implementation plan.
**Consume:** Task 1 typed contracts/predicates/results and exact timestamps.
**Produce:** `evaluate_scenario(manifest, events, *, profile, context) -> EvaluationResult` with fully validated input and deterministic evidence-linked verdicts.

- [ ] RED public-boundary tests: non-contract input, V1 event, list/tuple only, duplicates even identical, nested constructed/copied tampering, malformed timestamps, profile/scenario fingerprint mismatch, assertion/source mismatch, unsupported source version, missing/wrong bindings and declarations referencing wrong assertion or wrong scope/event set. Reconstruct plain model fields recursively before validation; do not serialize first and accidentally normalize invalid values. Reject extras. Avoid unvalidated timestamp instances bypassing component validation. Convert failures to safe ValidationEngineError, suppress raw chained errors.
- [ ] Implement _inputs.py validation including all budgets before evaluation. Unsupported version has stable specific code. Collection declarations are only for supported detection assertions; complete coverage spans entire context window and matching computed hashes. Public fingerprint helpers and evaluate must agree, including caller attestation hash ordering without cycles.
- [ ] RED baseline outcome tests then implement telemetry roots first and targets second, exporting results in manifest order. Scope + match use false-dominant ternary conjunction; explicit environment/source/time mismatches exclude. Count each scoped candidate evaluation and each join pair candidate once toward global comparison budget; internal field predicates are bounded by structural limits. Reject on comparison 1000001, never return partial verdict.
- [ ] RED same-pair tests then implement non-self joins: target and anchor all join fields must match on same pair and signed delta within inclusive range. Unknown fields are potential only when no known false remains, and positive existential witness wins. Track explicit sorted WitnessPair(target_event_id, anchor_event_id), supporting IDs and unevaluable candidates separately.
- [ ] RED missing-path tests then implement target anchor-first behavior, insufficient_fields, telemetry missing, detection completeness checks (all anchor intervals, timestamp overflow, collection unknown) and prevention-not-demonstrated. False-negative evidence is anchor evidence, not invented alert IDs. Missing telemetry may have none. Unsupported rules are inconclusive without pretending to query provenance.
- [ ] RED result integrity tests then collect only referenced evidence entries, preserving raw_event_ref/hash/schema_version. Include scope/profile/context/event-set identity hashes, all assertion outcomes/counts; aggregate exactly by spec precedence. No reads through evidence refs.
- [ ] Test 1 ns start/end/join boundaries, offset-equivalent timestamps, negative deltas, out-of-environment evidence, no self witness, mismatched source/provider, incomplete windows, unknown anchor, unrelated alert/block, every missing reason, permutation byte-identical JSON. Focused and full tests, self-review, commit `feat(validation): evaluate offline evidence with anchored verdicts`.

Minimal API call shape to test (builders produce explicitly synthetic reviewed contracts):

```python
result = evaluate_scenario(manifest, [activity, detection], profile=profile, context=context)
assert result.final_status == "Detected"
assert result.assertions[1].witness_pairs[0].target_event_id == detection.event_id
assert result.assertions[1].witness_pairs[0].anchor_event_id == activity.event_id
```

### Task 3: Adversarial acceptance, installed-package verification and user guide

**Own:** test_validation_acceptance.py, docs/VALIDATION_ENGINE.md; focused regression fixes to validation package if tests expose defects. No real ground truth profiles.
**Read:** AGENTS.md, PRD/ARCHITECTURE, approved spec; existing public validation API, test builders and task reports.
**Consume:** finished public API; **produce:** independently specified adversarial evidence and reproducible user handoff.

- [ ] Add RED tests for uncovered spec behavior (never manufacture failing tests unrelated to required behavior): malicious model_construct/model_copy nested states, unknown secret-looking keys and safe diagnostics, duplicate IDs outside time scope, collections with partial metadata/wrong hashes, all limit edges, same-pair cross-mix trap, unknown anchor candidates and positive existential precedence. If implementation already passes a case, record coverage-only test honestly instead of claiming RED.
- [ ] Fix demonstrated bugs minimally with observed regression RED/GREEN, preserve current contracts. Confirm no vendor/provenance access, no implicit fields, no input mutation, every result evidence ID originates in input. Include actual sanitized connector output intake when useful without claiming a real scenario pass.
- [ ] Write Vietnamese guide explaining direction A→future B, Python API exports, minimal runnable explicitly synthetic example, fingerprint/attestation construction, every status/reason, 1 ns windows, no inference, unsupported Cowrie session capabilities, limits and security assurance. No real collection declaration or approved real profile fabricated. Explain what user later supplies for lab review.
- [ ] Run full suite and pip check. Build wheel with existing setuptools via `python -m pip wheel . --no-deps --no-build-isolation --wheel-dir build/issue7-wheel`; create isolated verification venv under build, install wheel + already configured dependencies, run public API smoke from outside checkout and verify validation package import comes from installed site-packages. No new project dependency.
- [ ] Commit `test(validation): verify issue 7 acceptance and document offline use`. Report verification commands/output and remaining real-lab limitation. Controller obtains final whole-branch review; all finding fixes require covering tests and scoped re-review. Leave branch ready for user's independent tests, not merged.
