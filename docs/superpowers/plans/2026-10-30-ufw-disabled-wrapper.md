# Disabled-policy UFW Wrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admit the reviewed policy-disabled UFW wrapper without changing UFW.

**Architecture:** A small read-only qualification module supplies a stable
fingerprint through an injected OS reader. The host transaction installs a
private immutable record and boot guards revalidate it. Native tests exercise
the exact stock wrapper in isolated fixtures before a new check-first delivery.

**Tech Stack:** Existing Python 3.12 stdlib, systemd/busctl, nftables, OpenSSL,
iptables tools and unittest. Vendor sources are pinned test inputs, not runtime
downloads or new product dependencies.

**Spec:** `docs/superpowers/specs/2026-10-30-ufw-disabled-wrapper-design.md`.

## Global Constraints

- Issue #163 only; owner approved this amendment and subagent execution.
- Existing HTTP, CA, transport, rollback and source-authority limits still apply.
- Initially only UFW 0.36.2-6, policy disabled; no active-policy management.
- No UFW writes/commands that mutate state, hook execution or automatic reboot.
- Freeze static facts; fail on drift or unknowns, never infer empty arrays.
- Keep deployment facts, keys, credentials and vendor observations out of Git.
- Preserve old check ZIP/stage; no live apply before new qualification/check pins.

## Review Focus

1. A literal ENABLED=no alongside executable shell content must still refuse.
2. systemctl omission must not hide a nonempty command or injected environment.
3. Active guard must not bypass wrapper checks on an Indexer restart.
4. A missing/partial compatibility record must not broaden startup authority.
5. Native fixtures must prove behavior without altering host UFW/default firewall.

---

### Task 1: Read-only disabled-wrapper qualification

**Files:** create `deploy/wazuh/https_setup/ufw.py` and
`deploy/wazuh/tests/test_ufw.py`; extend the fixed SetupError vocabulary in
`contracts.py` only with `ufw_unsupported` and `ufw_drift`. No host integration.

**Interfaces:** frozen `RootFile` with content bytes, canonical path and held-read
stat metadata. `UfwReader` protocol exposes `root_file(path, limit) -> RootFile`,
`properties(unit, keys) -> dict[str,str]`, `run(name, *args) -> bytes`, and
`backend_identity(name) -> dict`. `qualify_disabled_ufw(reader, loader_state) ->
dict` checks eligibility and returns the closed stable fingerprint;
`verify_disabled_ufw(reader, loader_state, expected) -> None` requalifies and
compares it. Use `ufw_unsupported` for refused classification and `ufw_drift`
for a changed fingerprint; existing trusted-I/O errors retain their fixed codes.
No config bodies enter output.

Fingerprint exact outer keys: `schema_version=1`, `package_version`, `files`,
`unit`, `backends`. File entries contain canonical path, SHA-256, uid/gid,
permission mode and size only. Unit entries contain reviewed static facts/arrays
and package references, excluding runtime times/PIDs. Backend entries bind
selected canonical executable/content and nf_tables identity. Internal closed
field details are builder calls to record before Task 2 handoff.

- [ ] Write hostile/positive tests: shell tokens and duplicate/unknown keys,
  symlink/mode/link-count/size, modified package/hook, injected arrays/env,
  typed-zero omission, busy/transient unit, legacy/mixed backend and static drift.
- [ ] Run focused unittest and record missing implementation RED.
- [ ] Implement bounded parsing, exact vendor class, package-reference and
  nonexecute-hook checks. Query fixed D-Bus properties as needed; never source
  shell or invoke a hook. Trust local package metadata only at the declared OS
  boundary, not as an independent signature. Runtime eligibility is checked but
  volatile facts are not included in the fingerprint.
- [ ] Run qualification tests green once, self-review interfaces and commit.

### Task 2: Host transaction, private record and every-start guard

**Files:** modify `https_setup/host.py`, `transaction.py`, `firewall.py`,
`contracts.py` only for new fixed error codes if necessary; test_transaction.py,
test_components.py. A focused `https_setup/ufw_host.py` adapter may be created
instead of an unrelated host refactor. Update KIT_FILES for every new module.

**Interfaces:** consume Task1 protocol and functions via a Linux read-only adapter.
Record `/etc/aegis-wazuh-https/ufw-compat.json` has exact keys
`schema_version=1`, `profile_sha256` (canonical profile dict digest), `fingerprint`.
Expose `admit_firewall_loaders(...) -> dict|None` and
`verify_installed_firewall_compatibility(profile) -> None` on LinuxHost for both
guard modes. The original strict branch needs no exception record; an active
wrapper always requires a valid installed record at startup.

- [ ] Write REDs for strict old path, qualified exception, absent/malformed/partial
  record, profile mismatch, install interruption, check/apply drift, active-guard
  restart drift, rollback ordering and unchanged UFW/foreign state.
- [ ] Implement held no-follow root reads, fixed trusted backend alias resolution
  and the adapter. Classify only this exception; other loader refusal remains.
- [ ] Require fresh bounded C-locale CLI inactive status after actual executable
  provenance, full current nft baseline, and effective dependency/graph checks;
  preserve these host gates beyond the pure Task1 qualifier. Bind probe trust to
  frozen evidence and document the exact representation before native handoff.
- [ ] Include fingerprint in frozen facts/digests, durably install private record
  before guard use and capture its original state for recovery. Revalidate all
  startup conditions without calling full Indexer-active preflight from prestart.
- [ ] Add After=ufw.service to BOTH owned units, no UFW start dependency; retain
  every-start root verifier and no stop-delete. Validate dependency graph.
- [ ] Keep rollback HTTP-only: old localhost verified before owned-table removal;
  no UFW restore/repair. Unknown policy/record state retains protection/evidence.
- [ ] Run relevant component/transaction/qualification tests, self-review, commit.

### Task 3: Native vendor qualification and operator handoff

**Files:** tests/test_native.py, Run-SelfTests.py,
`.github/workflows/wazuh-http-operator.yml`, docs/manager/wazuh-http-preparation.md.
Private builder/metadata remain ignored and controller-owned.

**Interfaces:** add mandatory native ID
`deploy.wazuh.tests.test_native.NativeTests.test_ufw_disabled_wrapper_preserved`.
Sanitized proof adds vendor-input hashes, explicit fixture relocations and
booleans for UFW bytes/state preserved, no unintended start, lifecycle ordering,
allowed/denied traffic, foreign-rule preservation and fixture cleanup. Existing
seven required IDs remain mandatory. No portable skip qualifies this gate.

- [ ] Create RED native fixture with pinned exact official vendor bytes; no APT
  install/start of host UFW. Isolate filesystem and network operations, assert
  namespace before privileged firewall commands and track exact owned units.
- [ ] Separate real vendor behavior, adapter/D-Bus observations and synthetic
  positive admission. Do not mask unsupported fixture unit/root/argv differences;
  preserve actual facts when mapping owned namespace-scoped loader identities.
  Document that real full-class positive admission still needs the owner check.
- [ ] Exercise cold/active guard, normal wrapper stop/restart/direct reload,
  absent ExecReload, concurrent start/stop ordering, enabled-policy/static-record
  drift refusal, Manager allowed and another source denied across transitions.
  Compare host firewall and vendor state before/after and verify teardown.
- [ ] Implement runner/workflow source map and artifact checks for new required
  gate. Missing tools/proof or cleanup uncertainty fails, never silently skips.
- [ ] Update guide for the one-case exception, maintenance/requalification limit
  and separate vendor/reboot acceptance; no customer observation or credential.
- [ ] Run one portable operator suite; self-review and commit. Controller performs
  scoped/whole-amendment review, authorized push, exact-head native CI and fixes.
- [ ] Controller updates private manifest whitelist/required IDs, builds from Git
  blobs, verifies ZIP and fresh-extraction tests, then hands off only a NEW pinned
  readonly check. Never label the older kit as proving the new behavior.
