# Optional Wazuh HTTP Preparation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a separately reviewed optional root operator kit for HTTPS on
Wazuh 4.14.4, with a narrow firewall, verified rollback and no AEGIS coupling.

**Architecture:** Deployment values are supplied through a strict private JSON
profile. Small standard-library modules handle contracts, certificates, firewall
and a journaled host transaction. Native CI uses synthetic assets and isolated
namespaces/units; live Wazuh acceptance stays separate.

**Tech Stack:** Python 3.12, OpenSSL, nftables, systemd, unittest, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-29-wazuh-http-operator-design.md`.

## Global Constraints

- Issue #163 only; no product dependency or scenario-ground-truth changes.
- No real addresses, certificates, credentials or owner evidence in Git/CI.
- Optional operator kit; existing HTTPS installations skip it entirely.
- Only HTTP configuration, owned firewall table/guard, Indexer restart change.
- Preserve transport, CA bytes, old clients, Manager and application authority.
- Fail closed on ownership/link/shape/drift uncertainty; never flush all rules.
- Check is read-only and never reads the CA private key; apply needs frozen pins.
- No live apply command ships before required native synthetic tests pass.

## Review Focus

1. Home-directory archive replacement: securely stage an already-open regular
   inode; tests swap parents/path or members and must refuse or use pinned bytes.
2. YAML ambiguity: duplicate, quoted, nested, anchor/merge or multiline HTTP
   settings must refuse; unrelated lines must retain identical bytes.
3. Reboot/restart with stale active guard: exact rules verified on every start;
   native synthetic systemd service must not open after table deletion/drift.
4. Interrupted apply/recovery: inject failure before/after every side effect;
   journal precedes it and owned firewall survives uncertain rollback.
5. Local success is not external acceptance: status and delivery docs require
   Manager TLS, denied-source and old-client checks without inventing proof.

---

### Task 1: Profile, archive, certificate and firewall components

**Files:** Create `deploy/wazuh/https_setup/{__init__,contracts,certificates,firewall}.py`,
`deploy/wazuh/tests/test_components.py`, `deploy/wazuh/https-profile.json.example`.

**Interfaces:** `SetupError(code: str)` (safe fixed code); frozen `Profile` from
`load_profile(raw: bytes) -> Profile`, `profile.as_dict() -> dict`; fields
`schema_version, hostname, indexer_ip, manager_ip, config_path, ca_path,
leaf_path, ca_archive, ca_member, key_member, expected_ca_file_sha256,
expected_ca_der_sha256, expected_leaf_der_sha256` with no extra values.
`patch_http_config(raw: bytes, p: Profile) -> bytes`,
`archive_ca_members(raw: bytes, p: Profile) -> tuple[bytes, bytes]` is an offline
wrapper only. Live intake uses `read_archive_ca_members(source: BinaryIO,
p: Profile) -> tuple[bytes, bytes]` on a securely opened seekable uncompressed
tar: inspect headers, seek over unrelated bodies, read only the two targets,
reject compression/hidden trailers/links/duplicates/traversal and enforce bounds.
`read_vendor_ca_archive(source: BinaryIO, p: Profile) -> tuple[bytes, bytes]`
dispatches plain tar to that reader, or bounded streaming gzip/tar selection
which decodes/discards unrelated plaintext without retaining/logging/extracting
it. Reject concatenated gzip/trailing junk and cap both raw/decoded bytes at
32 MiB; per member 1 MiB, count 128. Never fully decompress into memory/disk.
`create_http_certificate(work: Path, p: Profile, ca_pem: bytes, ca_key: bytes,
old_leaf: bytes) -> tuple[bytes, bytes]` returns cert/key after real verification.
`firewall_text(p: Profile) -> str`, `verify_table(document: dict, p: Profile) -> None`,
`guard_unit() -> str`, `indexer_dropin() -> str` consume the installed profile
under `/etc/wazuh-indexer/aegis-http/profile.json` and fixed root-owned entrypoint
`/usr/local/lib/aegis-wazuh-https/Setup-Wazuh-HTTPS.py` with `guard-ensure` /
`guard-verify`. Table `inet aegis_wazuh_http_v1`, priority -50, TCP 9200.
TLS output `/etc/wazuh-indexer/aegis-http/tls/indexer-http{,-key}.pem`.

- [ ] Write unittest red cases for strict profile/duplicate JSON, unsafe IP/path,
  archive links/duplicates/limits/parent traversal, config ambiguity and exact
  preservation; firewall semantic mismatch and rendered boot/pre-start guards.
- [ ] Run focused tests and record expected missing-implementation failures.
- [ ] Implement the interfaces with no runtime dependencies. Profile requires
  Wazuh-owned paths within `/etc/wazuh-indexer`; archive absolute outside code;
  nonempty exact hostname and two distinct non-loopback private/global IPv4.
  Reject shell/template/control characters in every interpolated field.
- [ ] Add real OpenSSL tests for mismatched CA/key, wrong archived CA, exact IP
  SAN/EKU, preserved subject, PKCS#8 and bounded validity. Never log key bytes.
  On Windows unavailable OpenSSL can be an explicit local skip, required Linux
  mode must fail. Commands use argv, bounded timeouts and sanitized failures.
- [ ] Qualify actual vendor gzip input with a synthetic unrelated-credential
  marker and malformed/concatenated/bomb fixtures. Only CA/key returned or
  persisted; keep instrumented seek-only plain-tar regression unchanged.
- [ ] Run components once green; self-review; commit only sanitized code/tests.

### Task 2: Root host checks and recoverable transaction

**Files:** Create `deploy/wazuh/https_setup/{host,transaction,cli}.py`,
`deploy/wazuh/Setup-Wazuh-HTTPS.py`, `deploy/wazuh/tests/test_transaction.py`.

**Interfaces:** Uses Task 1 contracts. CLI commands `check --profile PATH`,
`apply --profile PATH --profile-sha256 HEX --check-sha256 HEX`, `status`,
`rollback`, and installed-only `guard-ensure`, `guard-verify`. Check outputs
`status, profile_sha256, check_sha256, facts`; caller freezes hashes from stdout.
Durable state `/var/backups/aegis-wazuh-https/intent.json`, exclusive lock beside
it; root-only exclusive backup subdirectory. A check digest covers stable host,
config/units/firewall/cert hashes and archive stat identity facts, excluding
moving time/PIDs. Never read/hash the complete live CA archive during check.
Check creates no files (including lock/intent) and never reads private CA key.

- [ ] Write red tests for wrong host/version/owners/paths, writable ancestors,
  concurrent operations, changed frozen state, existing unresolved intent and
  stable check digests. Use injected command/filesystem adapters for host tests.
- [ ] Implement bounded preflight of exact versions/identity/listeners/config,
  CA/leaf pins, archive metadata, full nftables baseline and firewall loaders.
  Refuse active/enabled nftables/UFW/firewalld loaders requiring unsupported
  ordering. Inspect actual systemd unit/sandbox and validate final drop-in.
- [ ] Implement trusted open/stage/backup, atomic writes/fsync and durable phases
  before each mutation. Copy only the kit's own manifest-pinned code into the
  fixed root-owned installed root. New file/dir metadata is explicit. Original
  files/unit/drop-in/firewall captured before change. Keep a root recovery log.
  Keep the CA archive open by verified inode/stat, use `read_vendor_ca_archive`
  and stage only selected CA/key bytes; never copy/hash the whole archive or
  retain unselected decoded bodies. Gzip skipping necessarily decodes bytes.
- [ ] Arm and verify guard before HTTP changes. Install fixed profile/code,
  TLS files, guard unit/drop-in and patch; daemon-reload; restart Indexer only.
  Every Indexer start includes root `ExecStartPre=+... guard-verify` as well as
  Requires/After on guard. Validate this works with actual unit sandbox before
  live apply. Root guard only ensures/verifies its exact table, never replaces
  a conflicting one. No ExecStop deleting firewall.
- [ ] Verify localhost certificate/TLS, exact 9200 and 9300 listeners and retained
  hashes; record `pending_external_validation`. `status` never upgrades this
  to accepted. CLI public errors are fixed vocabulary; no source config/key dump.
- [ ] Inject failures around each phase, recovery restart, TLS verification and
  table removal. Roll back original config/drop-in and old localhost service
  before removing only the owned table; if uncertain retain guard/intent and
  report `recovery_required`. Interrupted apply refuses blind retries. Temporary
  CA key gets unlinked on success/error; original archive never modified.
- [ ] Run task-focused and component tests green; self-review and commit.

### Task 3: Native qualification, guide and reproducible delivery

**Files:** Create `deploy/wazuh/tests/test_native.py`, `deploy/wazuh/Run-SelfTests.py`,
`docs/manager/wazuh-http-preparation.md`, and
`.github/workflows/wazuh-http-operator.yml`. Private delivery builder/facts remain
in the plan workspace, never Git.

**Interfaces:** Tests use Tasks 1/2 public functions and CLI. Self-tests require
explicit native mode on Linux, produce JSON counts and platform/required-test
results, and nonzero on missing/skipped native requirements.

- [ ] Write red native tests: real OpenSSL signing; nft syntax and allowed/denied
  sources in disposable network namespace; actual systemd disposable synthetic
  Indexer unit verifies correct guard ordering and refuses stale/deleted rules.
  Namespace/unit names random, timeouts bounded and teardown verified. Never
  mutate CI host default firewall or real Wazuh services. Fail missing capability.
- [ ] Implement isolated tests and Linux CI with exact source SHA and uploaded
  JSON proof. CI has no secrets, vendor credentials, real CA or live endpoint.
- [ ] Write Vietnamese guide: optional use, deployment variables, check then
  frozen apply, short Indexer outage, recovery status/rollback, external Manager
  TLS + denied-source + Dashboard/legacy checks and separate reboot permission.
  Explicitly distinguish native synthetic qualification from real Wazuh proof.
- [ ] Run local portable tests, push the already-authorized task branch to run
  native CI, inspect exact-head mandatory results; fix failures before packaging.
- [ ] Build a deterministic private lab ZIP containing sanitized helper/tests,
  one separate owner profile, instructions, checksums/review/native proof; include
  no CA/key/archive/credentials. Verify every archive member/hash and fresh
  extracted test invocation. Copy final ZIP/checksum to Downloads for user.
- [ ] Whole-kit independent review, resolve important findings, requalify changes
  and output only the pinned read-only check command first. Apply command follows
  frozen real-host check, never guessed drift hashes. No merge or live actions.
