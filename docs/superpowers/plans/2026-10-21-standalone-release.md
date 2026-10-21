# Standalone wheel and Windows EXE implementation plan

> **For agentic workers:** Use subagent-driven-development for the disjoint CLI and Windows packaging tasks. Verify the installed artifacts before claiming completion.

**Goal:** Deliver a wheel and local Windows EXE that replay reviewed public examples and serve the dashboard outside a checkout.

**Architecture:** Keep the canonical engine unchanged. A build step copies an explicit public resource allowlist plus a fresh frontend build into package data. The CLI exposes an offline demo and opt-in bundled dashboard. Freeze the installed wheel, never the editable checkout.

**Tech stack:** Python >=3.11, existing Pydantic/PyYAML, setuptools, Node 24 for the frontend build, build-only pinned PyInstaller for Windows.

**Spec:** The owner approved the first local EXE on 2026-10-21: bundled dashboard, six unchanged manifests and sanitized/synthetic demo, with writable results outside the installation. Shared-server identity and MSI rollout are subsequent designs.

## Global constraints

- Preserve all scenario ground truth, evidence bytes, hashes, canonical schemas and evidence IDs.
- No private evidence, credentials, live payloads, automatic rule changes or automatic collection.
- Existing dashboard behavior remains available; `--bundled` explicitly enables shipped resources.
- `demo --out` requires a new directory and never overwrites user data.
- Build-only PyInstaller is justified by Windows execution without a Python installation; runtime dependencies are unchanged.
- No public release, MSI, service installation or multiuser certification in this task.

## Review focus

- Windows paths containing Unicode and spaces must work outside all checkouts.
- A wheel must not silently omit the dashboard or resources.
- Existing output and failed demo creation must not lose user data.
- Freezing must include dynamically imported parsers and runtime license notices.
- A successful demo must not imply live lab coverage or independent operator acceptance.

## Task 1: Reproduce and package resources

- [x] Build baseline wheel, install into a fresh external venv; verify actual import origin.
- [x] Run eight validation cases, synthetic regression compare and dashboard APIs/assets with external assets.
- [x] Add failing tests for explicit resource selection and missing frontend failure.
- [x] Add resource locator, allowlist and setuptools build hook; run tests green.

## Task 2: Standalone CLI

- [x] Add failing tests for `demo --out`, no-overwrite/failure cleanup and `dashboard --bundled`.
- [x] Implement offline replay and version diagnostics; preserve original CLI semantics.
- [x] Run focused tests and review the task.

## Task 3: Windows distribution

- [x] Build script consumes an exact installed wheel and pinned build-only PyInstaller.
- [x] Build and smoke-test onedir, then onefile; no Python/Node commands in the runtime flow.
- [x] Document local usage, live prerequisites and MSI/shared-server follow-up gates.

## Task 4: Release verification

- [x] Add a reusable artifact smoke runner and CI checks outside source.
- [x] Run complete backend and frontend checks, fresh wheel installation and both frozen artifacts.
- [x] Review branch, fix concrete findings, and write artifact hashes and truthful platform limitations.

## Verification record

See [local acceptance](../../STANDALONE_RELEASE_VERIFICATION_2026-10-21.md). Resource, CLI and freeze tasks received independent review. Fixed findings: source-archive allowlist leakage, first-use output parent, frontend notice retention and editable-mode staging. No ground truth, connector or validation engine changes. Human/lab review and remote CI remain gates before merge; fresh Windows VM remains a gate before enterprise pilot.
