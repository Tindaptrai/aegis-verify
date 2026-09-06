# Issue #2 — Verification and review handoff

Branch: codex/issue-2-scenario-yaml-schema, based on main at dc09897.
Approved design: docs/superpowers/specs/2026-09-05-scenario-yaml-design.md.
Environment: Windows, Python 3.13.14, Pydantic 2.13.5, PyYAML 6.0.3, pytest 9.1.1.

## Delivered

- Strict, frozen ScenarioManifest / ScenarioAssertion / ScenarioSafety models,
  logical source enum, expected outcome enum and localized relation validation.
- Read-only file/text YAML loader with bounded input, event preflight, duplicate
  key rejection, restricted tags/scalars, UTF-8 checks and sanitized public errors.
- Existing three draft manifests load without modification or evaluation.
- Vietnamese schema guide and post-Issue-2 review/fixture handoff plan.

## Actual checks

1. Created a separate .venv in this Issue #2 worktree, installed editable package
   and confirmed aegis_verify.__file__ points at this checkout. Baseline: 180 passed.
   The shared Issue #1 venv was not remapped or modified.
2. New model tests first failed at missing ScenarioManifest import. With initial
   typed fields: 12 failed / 93 passed. Failures reproduced missing duplicate,
   parent/source relation, enum coercion, ordered-collection and safety guards.
   After validators: 285 passed (180 existing + 105 scenario-model cases).
3. New loader tests first failed at missing scenario_loader import. Initial
   full loader test run: 69 passed / 1 failed / 2 setup/cleanup errors. The latter
   were test harness defects: a huge parametrized value used as pytest test ID,
   and a literal marker embedded in the test's own traceback source line. Tests
   were corrected with short IDs and variable input; 71 loader cases passed.
4. Bounded self-review found malformed numeric tags escaping as IndexError and
   legacy !!str mapping shorthand silently discarding mapping members. New
   regression tests: 8 failed / 1 passed / 71 deselected before the fix. Added
   tag/node-shape checks and controlled scalar-conversion errors; full suite:
   365 passed (180 prior + 105 model + 80 loader cases).
5. pip check: No broken requirements found.
6. Built wheel using pip wheel --no-deps . --wheel-dir dist. Installed wheel with
   [test] extras in a new build/package-check venv. From build/, ran the full suite
   with --import-mode=importlib: 365 passed in 6.45s; pip check clean. Printed
   package and scenario_loader paths: both under that venv's site-packages.
7. Executed the Python example extracted from docs/SCENARIO_SCHEMA.md, not a
   retyped variant: SCN-001 detected 3; SCN-002 prevented 4; SCN-003 detected 4.
   These are authored expected outcomes and assertion counts, not detection results.
8. Additional in-memory probe of 144 scalar/tag combinations and 500 deterministic
   random malformed snippets (seed 2): 644 cases, 11 accepted and serializable,
   633 controlled ScenarioLoadError rejections; no unexpected exception observed.
9. git diff --check clean. git diff --exit-code dc09897 -- scenarios
   backend/app/models/canonical_event.py produced no differences. No ground-truth,
   CanonicalEvent behavior, live connector, production log or scenario execution
   changes. Wheel/build/.venv artifacts remain ignored and are not staged.

Test counts include parametrizations; they are not counts of distinct features.
Final local pytest/diff/package checks are rerun before the documentation commit.

## Acceptance mapping

| Issue #2 criterion | Evidence |
| --- | --- |
| ID/name/version/safety/sources/outcome/assertions defined | scenario.py; SCENARIO_SCHEMA.md |
| Stable assertion ID and evidence-oriented expectation | Authored IDs/descriptions preserved, uniqueness/parent checks; prose semantics still require human review |
| Three committed manifests validate | test_committed_manifests_load_without_writes + documented example |
| Reject missing IDs, bad outcome, duplicate IDs and malformed sources | test_scenario.py and loader diagnostics tests |
| Errors identify scenario and field | ScenarioLoadError; valid scenario ID or caller source label; field path or parser line/column |
| No silent runtime ground-truth rewrite | Frozen nested models/tuples, no write API, duplicate/merge/alias rejection, input isolation and unchanged-file tests |
| Existing tests remain green | All 180 Issue #1 cases included in 365-case editable and wheel runs |

## Review limits

- This is a self-review, not an independent reviewer or lab validation. No further
  actionable defect was found in this bounded review after the two parser fixes.
- Only Windows/Python 3.13.14 was run; no Python 3.11/3.12 or Linux test run.
- No live evidence, matching predicates, correlation window or Pass/Fail engine.
  Assertion descriptions remain human-reviewed prose, as explicitly approved.
- Resource limits are bounded defenses, not a proof against all hostile input.
  File permission-error handling is implemented but was not exercised by changing
  Windows ACLs. No benchmark, coverage percentage or formal fuzzing claim is made.
- Pydantic generated JSON Schema is not a replacement for runtime validators or
  YAML policy. Frozen objects are not a sandbox against arbitrary Python code.
- Source labels/paths are caller-controlled; public exception formatting suppresses
  raw values/chained parser snippets, not arbitrary inspection of traceback locals.

## User-side handoff

```powershell
cd 'I:\AEGIS-VERIFY\.worktrees\issue-2-scenario-yaml-schema'
& '.\.venv\Scripts\python.exe' -m pytest backend/tests -q
& '.\.venv\Scripts\python.exe' -m pip check
& '.\.venv\Scripts\python.exe' -c "import aegis_verify; print(aegis_verify.__file__)"
```

User confirmation of Issue #2 tests/review is pending. No push, PR or merge was
performed for Issue #2. The next-step plan is 2026-09-06-after-issue-2.md in this
directory; no Issue #3 implementation has begun and no credentials are required.
