# Fixture CI (Issue #32)

`.github/workflows/ci.yml` runs for pull requests, pushes to `main`, and manual
dispatch once available on the default branch. All PRs are checked, including
documentation-only changes; there are no path filters that leave required checks
pending. New runs supersede older runs for the same PR/ref.

- Backend: complete pytest suite and wheel build on Windows/Linux, Python 3.11/3.12.
- Frontend: `npm ci`, full Vitest suite, TypeScript and Vite build on Node 24/Linux.
- Only `contents: read`; checkout does not persist credentials. Official Actions
  are pinned to commit SHAs. No `pull_request_target`, deployment, secrets,
  private evidence upload, self-hosted lab runner or live connector invocation.
- Tests use fixtures and local loopback servers; dependency installation still
  requires public package registries. This is not a network-isolated sandbox.
- Jobs have time limits and do not publish a release or change source files.

The Windows FIFO skip is expected; Linux must execute that test. A green fixture
suite is software verification, not lab collection assurance or production approval.
Test/build output is visible in Actions; report files and credentials are not supplied.

For equivalent local checks, install `.[test]`, run `python -m pytest -q -rs`,
then run `npm ci`, `npm test`, `npm run build` inside `frontend`.

Required branch checks are an owner-managed repository setting. This PR adds CI
but does not change branch protection or bypass merge requirements.

Official references: [Python CI](https://docs.github.com/en/actions/tutorials/build-and-test-code/python),
[setup-node](https://github.com/actions/setup-node),
[setup-python](https://github.com/actions/setup-python).
