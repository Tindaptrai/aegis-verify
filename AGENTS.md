# AEGIS Verify Agent Instructions

1. Read `docs/PRD.md` and `docs/ARCHITECTURE.md` before modifying code.
2. Implement only the requested GitHub issue.
3. Do not add dependencies without justification.
4. Do not hard-code IP addresses, passwords, tokens, or connector URLs.
5. All connector outputs must use the canonical event schema.
6. Security conclusions must reference evidence IDs.
7. Do not fabricate log events in production code.
8. Add or update tests for every behavior change.
9. Never modify scenario ground truth without explicit approval.
10. Do not commit secrets, real credentials, certificates, or unsanitized evidence.

## Engineering constraints

- Keep source-specific parsing inside `connectors/`; validation code consumes only
  canonical events.
- Preserve unknown source fields in the raw evidence reference, but represent absent
  canonical fields as `null`. Never guess values.
- Fixture connectors are V0. Do not introduce live-system dependencies until the
  fixture-driven validation path works end to end.
- Keep safe scenario execution separate from evidence evaluation.
- Prefer small, reviewable changes tied to one issue and its acceptance criteria.

## Required workflow

1. Confirm the issue scope and acceptance criteria.
2. Create a focused branch.
3. Implement code and tests.
4. Run the relevant local checks.
5. Request human review and lab validation.
6. Merge only after evidence and tests have been reviewed.
