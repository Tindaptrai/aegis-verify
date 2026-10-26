# AEGIS checkpoint — resumed native CI investigation

Date: 2026-10-26 (Asia/Saigon).
Status: RESUMED at the owner's explicit request. The earlier pause is revoked.

The historical checkpoint below records the original pause, not the current task state.
Tasks 1–6 and the scoped Task7/final code reviews have since been accepted. The native
Windows acceptance gate remains mandatory; review approval alone does not satisfy it.

## Current continuation

- Branch/worktree and issue remain the same as below.
- Source `4f098189f67675d7eae0c60b6238742e87fdaad1` passed all four Manager CI jobs
  in run [40291510662](https://github.com/Tindaptrai/aegis-verify/actions/runs/40291510662).
  Agent Windows CI failed because the generated fixture channel contained no seed.
- Diagnostic source `901c01b58e1b47cb8722b76ab3257f3993390258`, run
  [40300407396](https://github.com/Tindaptrai/aegis-verify/actions/runs/40300407396),
  isolates the fixture boundary: only the UInt32 payload/template arm observed the
  exact event (172 ms); empty control, message-only and ACL-only arms remained empty.
  This is fixture evidence, not a general claim about all zero-payload Windows events.
- The resulting test-only correction adds one UInt32 Seed=1 field to the generated
  manifest and C# writer. Enablement, exact event identity, deadlines, ACL assertions
  and all seven required native categories remain unchanged. Temporary differential
  experiments are retired from normal CI; source and diagnostic artifact retain the
  experiment. Failure-only bounded identity diagnostics remain.
- The same run exposed an existing supervisor test handshake cancellation race.
  The test now covers cancellation both during and after its handshake with
  deterministic synchronization. Production supervisor behavior is unchanged.
- Correction `6f1a6e7ed6ced11697d05683d4182a396ae78278` passed all four Manager
  jobs in [40302509376](https://github.com/Tindaptrai/aegis-verify/actions/runs/40302509376)
  and the Linux Agent job in [40302503525](https://github.com/Tindaptrai/aegis-verify/actions/runs/40302503525).
  Windows completed all five fixture categories; published installation then failed.
- Closed diagnostics at source `f3e0f0c6d17f88992b3702108f49fbebabb448fc`, run
  [40304689562](https://github.com/Tindaptrai/aegis-verify/actions/runs/40304689562),
  locate the failure at installation with HRESULT -2147024809. An ordinary-file
  PowerShell 5.1 regression reproduced that error when updating the control record
  from prepared to promoted: `File.Replace` received an empty backup-path string
  instead of CLR null. The narrow correction passes an explicit CLR null and retains
  atomic replacement. New tests exercise real record writes and failed replacement.
- The control-record correction at `b9dd54807f78637d668c61bc75c1790e78d8ada9`
  passed actual installation, Running status and mTLS presence in Agent run
  [40306550573](https://github.com/Tindaptrai/aegis-verify/actions/runs/40306550573).
  Linux Agent and all four Manager jobs in
  [40306550424](https://github.com/Tindaptrai/aegis-verify/actions/runs/40306550424)
  passed at that same source. Windows subsequently failed the MissingVendor test;
  its original fixed error label was missing from the diagnostic allowlist.
- Test-only follow-up preserves those fixed labels and corrects Cleanup to validate
  preserved identity using the verified package CLI after uninstall removes the
  installed CLI. UUID, marker, package and deletion-path checks remain mandatory.
- Next: exact-source hosted CI must identify the remaining MissingVendor failure
  and verify cleanup. Do not merge, deploy or claim Ready before required gates
  and human lab review.
- Detailed decisions, local verification and fresh CI results are recorded in
  `.superpowers/sdd/2026-10-25-windows-web-job/progress.md`; the latest delivered
  evidence bundle is the portable counterpart. No live VM/scenario work was done.

## Historical pause record (superseded)

## Resume location

- Issue: https://github.com/Tindaptrai/aegis-verify/issues/161
- Worktree: C:/Users/kuroh.DESKTOP-E4H07CM/.codex/worktrees/demo-launcher-logo/AEGIS-VERIFY
- Branch: codex/windows-web-job-single
- Last product commit: 31395e750fb88ffdc4c65b767a0b6f0ff74d7ca3
- Primary checkout I:/AEGIS-VERIFY was not used for these changes.
- Spec: docs/superpowers/specs/2026-10-25-windows-web-job-design.md
- Plan: docs/superpowers/plans/2026-10-25-windows-web-job.md
- Detailed recovery ledger: .superpowers/sdd/2026-10-25-windows-web-job/progress.md
- All implementation changes are committed. This checkpoint is documentation only.

## Accepted task reviews — do not reimplement

1. Contracts/models: b80a05e + f445448; scoped fix review accepted.
2. Authority/ownership/API: 8f3f130; accepted. Later test-only PostgreSQL fixture
   fix 9c63fb3 accepted (production locking unchanged).
3. Readiness/worker/source health: b0bb3c8 + 37bb830; accepted after scope-proof
   identity/epoch and EVT_VARIANT ABI fixes.
4. Durable Windows supervisor/native kernel/journal: 0a4ea53 + c2d6343; accepted
   after per-file PowerShell origin/policy fix. Policy supports only explicit
   RemoteSigned/Unrestricted and fixed-drive MyComputer files without Zone.Identifier;
   unknown/default/signature-dependent cases remain NotReady. No policy override.
5. Frozen collection to real canonical intake/engine: 75354c4; accepted.
6. Manager UI: 4af5b89 + 93fd8f8; accepted, actual built-fixture desktop/narrow QA done.

Keep Gap -> Rule Fix -> Re-test -> Pass evidence-backed. Health, receipts and exit0
are not detection evidence; unknown binding/collection assurance stays unknown.
Linux remains presence-only; uploaded Catalog ZIPs do not become executable.
Only one explicitly provisioned paired Windows and one globally active job are in scope.

## Task7 implemented; independent review is NEXT

Three disjoint author commits, all part of Task7:
- 5521b4620a90489fa2157f45f1d2e3b4699565dd: actual Linux Manager-worker systemd gate.
- b2643b047ba96f8728567bdd6596bfa8d2af50e1: version0.3, exact execution RSA3072,
  canonical packaging, required result-derived CI gates and docs.
- 31395e750fb88ffdc4c65b767a0b6f0ff74d7ca3: Windows opt-in provisioning,
  descriptor/upgrade recovery and disposable native fixtures.

Prepared combined review package (not dispatched before pause):
.superpowers/sdd/2026-10-25-windows-web-job/review-c2d6343..31395e7.diff
BASE c2d6343d697c2f3a2cd1f01784bd35fc239850a2, HEAD 31395e750fb88ffdc4c65b767a0b6f0ff74d7ca3.
Contains 3 commits, 38 files, 296786-byte review package.

Read these reports plus task7/global/ownership briefs for independent spec+quality review:
- task-7-report.md (native)
- task-7-integration-report.md
- task-7-worker-service-report.md
All reports/briefs are under the ledger directory above.

Original implementers available for scoped fixes:
- /root/execution_task7_provisioning (native, Astra)
- /root/execution_task7_integration (version/crypto/package/CI/docs, Sol)
- /root/execution_task7_worker_service (Linux test gate, Sol)

No commit or shared .NET build semaphore remains granted; all agents are completed.
Serialize staging/commits and shared .NET build/test execution if writers are resumed.

## Verification already recorded

- Backend regression: 3903 passed, 3 skipped (Task5); do not repeat without a reason.
- Task5 focused/compatibility: 53 passing.
- Task4 base: execution47, required inert-native11, legacy29; fix raised native count13.
  Fix focused policy/origin/preflight/supervisor/diagnostics/runner checks passed.
- Task7 integration: execution54 plus focused state/enrollment/compatibility checks;
  packaging+CI runner69; signing/compatibility21; contracts/vectors18 including
  7 actual required Python/C# vector cases. Native writer later compiled the final
  test-only fixture change cleanly; no unqualified final-head full-suite claim.
- Native Task7: pure PowerShell20, refusal test1, clean Release compilation;
  actual elevated SCM/channel/SID/default-ancestor/upgrade fixtures authored but NOT run locally.
- Linux worker: local harness/TLS/syntax checks and focused regressions passed;
  actual systemd/PostgreSQL methods NOT run locally.

Early diagnostic CI is NOT final Task7 CI:
- https://github.com/Tindaptrai/aegis-verify/actions/runs/40218108381
  Source37bb830: Windows70/Linux71 managed, packaging and published-presence passed.
- https://github.com/Tindaptrai/aegis-verify/actions/runs/40218632494
  Source37bb830: overall FAILED (missing vector harness wiring and legacy fixture).
  Eight new PostgreSQL races and nginx execution mTLS cases individually passed.
  Fixture fixed9c63fb3; harness wiring implemented in Task7 but final CI not run yet.
- Owner-host full TLS had a baseline X509Chain/stall failure; fresh early Windows
  CI passed it. Do not weaken TLS or turn an earlier result into a final-head pass.

## Exact continuation order

1. Read this checkpoint and ledger; verify branch/status. Do not redispatch completed tasks.
2. Dispatch ONE independent capable Task7 reviewer with prepared diff + all three
   reports, master/global/ownership briefs. Both spec and quality verdicts required.
3. Push reviewed/local feature commits to its own branch and run exact-head CI
   (agent-connection + manager-first-flow, including new actual native/systemd gates).
   Tests may run while review proceeds; no live VM or production action.
4. Resolve findings/CI failures through original authors with focused RED/GREEN and
   scoped rereview. No secret/ground-truth/policy bypass, no false native pass.
5. Once all task gates are accepted, perform broad whole-branch review on the most
   capable model, final appropriate checks, and prepare reviewable delivery/draft PR.
6. Stack the issue161 PR on codex/catalog-zip (existing draft PR160 at7c6fbe80).
   Attach every created PR with Codex attach_artifact. No issue161 PR exists yet.
7. Preserve reports/proof outside the ignored SDD folder before eventual cleanup.
   Human/evidence review and separately approved real vendor/SCN001/reboot lab
   validation still precede merge. Do not merge/deploy/hand off real targets automatically.

Remote feature branch currently stops at37bb830; later commits are LOCAL only.
No final CI was dispatched after Task7, no live Manager/agent/Wazuh upgrade, rule
change, ownership transfer or actual SCN001 run occurred in this implementation.
User's prototype server/tab was left untouched. Root temporary QA servers/tabs
were already closed. All delegated agents are finished; no background work scheduled.

Suggested user resume phrase: tiep tuc tu checkpoint AEGIS.
