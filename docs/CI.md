# Fixture CI (Issue #32)

`.github/workflows/ci.yml` runs for pull requests, pushes to `main`, and manual
dispatch once available on the default branch. All PRs are checked, including
documentation-only changes; `ci.yml` has no path filters that leave required checks
pending. New runs supersede older runs for the same PR/ref.

- Backend: complete pytest suite through an editable install. Pull requests run Linux with
  Python 3.12 only; pushes to `main` and manual dispatch run Linux with Python
  3.11/3.12/3.13 and Windows with 3.11 and 3.13 (the oldest and newest supported
  versions; 3.12 is the usual local development version). The split saves Actions
  minutes on this private repository, where Windows minutes bill double
  (2026-09-27, after the monthly allowance ran out). To check a branch on the full
  matrix before merging, run the workflow manually on that branch (Actions ›
  Fixture CI › Run workflow).
- Windows PR checks (`windows-pr.yml`, #114): a pull request that changes code with
  Windows-specific behaviour also runs the backend suite on Windows/Python 3.13.
  The trigger paths are ACL creation (`private_fs.py`), the dashboard and
  Operations, the demo pipeline and SCN-001 runner, intake I/O, the Wazuh
  collectors, PowerShell scripts, CLI and packaged resource handling, their tests,
  packaging/build configuration and the workflows. #111 passed Linux PR checks but failed 311 tests on the
  (elevated) Windows runners; this job exists to catch that before merge. It is
  path-filtered, so it is not suitable as a required check. A Windows job costs
  about 12 billed minutes.
- Frontend: `npm ci`, full Vitest suite, TypeScript and Vite build on Node 24/Linux.
- Installed wheel: every PR, push to `main` and manual run builds and tests a wheel
  on both Ubuntu and Windows with Python 3.13 and Node 24. Each job builds fresh
  frontend assets, then runs `pip wheel . --no-deps`; the wheel resource hook
  requires that dashboard build. The job installs the one newly built wheel and
  its runtime dependencies into a new virtual environment under `RUNNER_TEMP`,
  outside the checkout, and runs `scripts/smoke_distribution.py` using that
  environment's Python. This does not reuse the editable install or test fixtures
  from the working checkout at runtime.
  - The smoke test checks eight public scenario cases, two comparisons, actual
    dashboard HTML/JS/CSS, the six-scenario registry and report APIs.
  - Negative checks cover evidence hash mismatch, malformed/unsupported reports,
    preserving an existing demo directory and read-only dashboard inputs.
  - SCN-002/003/004 data are sanitized derivatives; SCN-005/006 and the Gap/Fix
    example are explicitly synthetic. No scenario payload or live collector runs.
  - The JSON result and temporary wheel/environment stay on the ephemeral runner;
    no build artifact is uploaded or published. Windows EXE freezing is a separate
    local build and is not performed by this workflow.
- Only `contents: read`; checkout does not persist credentials. Official Actions
  are pinned to commit SHAs. No `pull_request_target`, deployment, secrets,
  private evidence upload, self-hosted lab runner or live connector invocation.
- Tests use fixtures and local loopback servers; dependency installation still
  requires public package registries. This is not a network-isolated sandbox.
- Jobs have time limits and do not publish a release or change source files.

The Windows FIFO skip is expected; Linux must execute that test. A green fixture
suite is software verification, not lab collection assurance or production approval.
Test/build output is visible in Actions; report files and credentials are not supplied.

For equivalent source checks, install `.[test]`, run `python -m pytest -q -rs`,
then run `npm ci`, `npm test`, `npm run build` inside `frontend`. Source tests do
not require the frontend build. Building a distributable wheel does require it;
install that wheel in a new environment outside the checkout and run
`python scripts/smoke_distribution.py --python <new-environment-python> --result <result.json>`
to check the installed distribution independently.

Required branch checks are an owner-managed repository setting. This PR adds CI
but does not change branch protection or bypass merge requirements.

Official references: [Python CI](https://docs.github.com/en/actions/tutorials/build-and-test-code/python),
[setup-node](https://github.com/actions/setup-node),
[setup-python](https://github.com/actions/setup-python).
