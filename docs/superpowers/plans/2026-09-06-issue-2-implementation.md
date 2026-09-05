# Scenario YAML Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans. Execute sequentially
> in the existing Issue #2 worktree with test-first checks and self-review.

**Goal:** Validate the three unchanged draft manifests without executing them or
interpreting their prose assertions as executable detection predicates.

**Architecture:** Frozen Pydantic domain models receive plain data from a bounded
YAML reader. The reader applies YAML policy before constructing objects and emits
sanitized diagnostics. No event parser, evaluator or writer is introduced.

**Tech Stack:** Python >=3.11, existing Pydantic 2.13.5 / pytest 9.1.1,
PyYAML 6.0.3 (version checked on PyPI), standard-library pathlib/dataclasses.

**Spec:** `docs/superpowers/specs/2026-09-05-scenario-yaml-design.md`, approved by
the user before this implementation plan.

## Global Constraints

- Only Issue #2. Do not modify any bytes in scenarios/ or CanonicalEvent behavior.
- Keep missing tags null, explicit [] empty; preserve text and collection order.
- V0 status draft, outcomes detected/prevented; required safety false/true.
- Sources: sysmon, powershell, wazuh, suricata, pfsense, cowrie; no provider mapping.
- Maximum 256 KiB UTF-8 input including BOM, 20 collection levels (root=1),
  10,000 nodes including keys. No anchors, aliases, merge keys or custom tags.
- Public errors do not include raw input, parser snippets, unknown key names or
  exception tracebacks from the underlying parser. Caller owns source-name privacy.
- Use `.venv/Scripts/python.exe` inside the Issue #2 worktree. Do not remap the
  shared Issue #1 venv. No push, merge or live lab calls in this implementation.

## Task 1 — Pure scenario contract

Files: create backend/app/models/scenario.py, backend/tests/test_scenario.py;
modify backend/app/models/__init__.py for exports.

Produces: ScenarioSource, ExpectedOutcome, ScenarioSafety, ScenarioAssertion,
ScenarioManifest with standard model_validate/model_validate_json/model_dump_json.

- [ ] Add tests with an artificial scenario dictionary (SCN-900, one wazuh
  assertion SCN-900-A01, draft version 0.1.0, safe flags false/true).
  Example regression contract:

  ```python
  data['assertions'].append(dict(data['assertions'][0]))
  with pytest.raises(ValidationError):
      ScenarioManifest.model_validate(data)
  ```

- [ ] Run `python -m pytest backend/tests/test_scenario.py -q` before creating
  the module and observe the missing contract; add typed fields, then exercise
  boundary tests to distinguish missing cross-field checks from import errors.
- [ ] Implement strict nonblank UTF-8 strings with AfterValidator, ASCII ID
  patterns anchored at the actual end, strict boolean fields followed by safety
  checks, string enums with before validators rejecting bytes, frozen nested
  models and tuple collections with before validators accepting only list/tuple.

  ```python
  model_config = ConfigDict(extra='forbid', frozen=True, hide_input_in_errors=True)
  expected_sources: Annotated[tuple[ScenarioSource, ...], Field(min_length=1)]
  tags: tuple[NonBlank, ...] | None = None
  ```

- [ ] Add model-level relation validation: duplicate source and assertion IDs,
  parent/child ID prefix, membership of assertion source and coverage of all
  declared sources. Give failures a stable field location with Pydantic
  ValidationError.from_exception_data and fixed error messages, never raw values.
- [ ] Parametrize omissions, bad types, malformed IDs/versions, unsupported
  status/outcome/source, safety coercion, unicode, empty/unordered collections;
  test both JSON paths, list isolation and nested immutability.
- [ ] Run focused plus full suite; commit model and tests only after green.

## Task 2 — Bounded YAML policy and public loader

Files: create backend/app/_scenario_yaml.py (private parser policy),
backend/app/scenario_loader.py (IO/public diagnostics),
backend/tests/test_scenario_loader.py; modify pyproject.toml to add PyYAML==6.0.3.
The private policy split keeps parsing independent of public error presentation.

Consumes ScenarioManifest. Produces:

```python
def parse_scenario_yaml(text: str, *, source_name: str) -> ScenarioManifest: ...
def load_scenario(path: str | Path) -> ScenarioManifest: ...
```

ScenarioLoadError exposes source_name, scenario_id (valid ID or None), and an
immutable tuple of ScenarioDiagnostic(code, field, line, column). Public messages
contain only these sanitized fields. Private policy exceptions carry fixed codes
and positions, not source snippets. Scalar/model values never appear in diagnostics.

- [ ] Add a real minimal YAML string and load actual repository manifests in
  tests. Run before implementing loader to observe missing entry points.
- [ ] Add PyYAML==6.0.3 and install editable package into the isolated venv.
  Use the documented event stream to reject tags/anchors/aliases and enforce
  collection depth/node/document budgets before composing an object graph:

  ```python
  for event in yaml.parse(text, Loader=ManifestSafeLoader):
      if isinstance(event, AliasEvent) or getattr(event, 'anchor', None) is not None:
          raise YamlPolicyError('yaml_alias', event.start_mark)
  ```

- [ ] Subclass SafeLoader without mutating its global registries. Limit the
  boolean resolver to lowercase true/false. Reject duplicate keys before value
  construction, all non-string mapping keys and merge keys. Permit only standard
  scalar/collection tags; reject unsupported scalar tags instead of constructing
  dates, bytes or Python objects. Standard numeric values remain numbers and are
  rejected by strict domain fields, not converted to strings.
- [ ] Convert YAML policy/parser/Unicode exceptions into fixed diagnostics;
  preserve mark line/column as one-based. Root must be a dict. Obtain scenario_id
  only if root id matches the strict public ID pattern. Convert model error loc
  components into allowlisted field names/indices; replace unknown keys with a
  fixed `<unknown>` segment, including suspicious nested paths.
- [ ] Implement byte limit and strict UTF-8 checks for text and bounded file read:

  ```python
  with Path(path).open('rb') as stream:
      raw = stream.read(256 * 1024 + 1)
  # Reject oversized bytes before UTF-8 decoding; strip one leading BOM only.
  ```

- [ ] Cover duplicate keys at every nested level, syntax/multi-document/empty
  roots, dangerous tags, aliases, merges, non-string keys, bool spellings,
  malformed UTF-8 and escaped surrogates. Assert fixed code/location and that an
  untrusted marker does not appear in formatted exceptions or traceback output.
- [ ] Exercise exact byte boundary including BOM and multibyte UTF-8; depth 20/21
  and node 10,000/10,001 through parser policy before model validation. Test a
  thousands-deep input produces controlled depth rejection rather than recursion.
- [ ] Use tmp_path for genuine read/no-write/missing-file/invalid-file tests.
  Test no environment interpolation and no mutation of global PyYAML behavior.
- [ ] Run focused/full suite and pip check; commit after the green checkpoint.

## Task 3 — Delivery verification and next-step plan

Files: create docs/SCENARIO_SCHEMA.md,
docs/superpowers/plans/2026-09-06-issue-2-verification.md,
docs/superpowers/plans/2026-09-06-after-issue-2.md;
update README.md and backend/README.md; mark this plan completed with evidence.

- [ ] Document every model field and loader policy, sample Powershell/Python
  commands, exception contract and the fact that validated draft is not approval
  to execute. Explain scenario version is a scenario revision, not event schema
  version; document current v0.1 contract through this guide and generated schema.
- [ ] Run the documented example against all three repo manifests and confirm
  literal IDs, outcomes and assertion counts 3/4/4, without altering their bytes.
- [ ] Build wheel and install into a separate clean venv; run tests from outside
  the source checkout using --import-mode=importlib and print imported module paths.
- [ ] Self-review the complete diff for acceptance criteria, parser safety,
  bounded allocations, diagnostics, strictness and immutable nested structures.
  Write failing regressions before fixing any newly confirmed defect.
- [ ] Run fresh full pytest, pip check, git diff --check and
  `git diff --exit-code dc09897 -- scenarios backend/app/models/canonical_event.py`.
- [ ] Record actual results, review limits, package checks, Python version and
  user-side commands. Inspect current Issue #3 read-only for the next-step plan.
- [ ] Plan human test/review → PR/merge Issue #2 with approval → fixture handoff
  and Issue #3 design. Specify sanitized Wazuh samples needed, never fabricate
  production/lab evidence or ask for credentials. Do not implement Issue #3.
- [ ] Commit documentation; preserve branch/worktree for user verification.
