# Paired Windows web execution (0.3)

The 0.3 connection agent installs in presence-only mode. Execution is an explicit
local administrator opt-in for one reviewed Windows device and one active job,
provider `reviewed-scn001-windows/1`. Linux remains presence-only. Catalog uploads
do not grant execution authority. The v1 agent and its signed history remain separate.

## Review private inputs first

Before provisioning, the owner reviews the exact paired UUID/generation/certificate,
environment, authoritative Wazuh mapping, legacy ownership handoff, registered
source UUID/revision/output root, and the per-device kit/study/evaluation/rule pins.
Use separate private locations for immutable reviewed assets, identity/journal and
create-new run output. Do not use a Git checkout for writable output. Do not copy
pilot configuration or put web/Indexer credentials on the endpoint.

The private installation profile, installed grant and `manager-execution-v2` public
pin are explicit inputs. Generate a separate **exact RSA3072** execution signing
key; RSA2048 and RSA4096 are rejected for this protocol. Keep the v1 signing key,
TLS CA and agent identity key unchanged. The public package contains no per-device
profile/grant/pin, kit/study, identity, configuration, key, certificate or log.
Its `execution/SCN-001-powershell-execution.yaml` is the exact 887-byte reviewed LF
asset (SHA256 `4f00335ddd0e39979d90852122642b945faa03ba50d7e9189fe282662bad84a9`).
Its presence does not authorize installation or execution of a scenario.

## Install, upgrade and enable locally

Follow `AGENT_CONNECTION_RUNBOOK.md` to verify the package/checksums/source commit,
then install or upgrade presence using Windows PowerShell 5.1 as administrator.
Review all three scripts. Use `-NoLogo -NoProfile -NonInteractive -File`; supported
commands do not override execution policy or change policy/origin metadata.

Execution readiness supports only an explicit effective `RemoteSigned` or
`Unrestricted` policy under the actual service identity. All three reviewed scripts
must be on a fixed local drive, map to MyComputer through Windows zone evaluation,
and have no `Zone.Identifier` stream. Undefined/default, Restricted, AllSigned,
Bypass, unknown/error or signature-dependent policy branches remain NotReady.
WLDP/SAFER must also allow each file, and the contained read-only runner must
succeed under `NT SERVICE\AegisAgent`. Organization policy/signing decisions remain
owner-controlled; this guide supplies no command to relax them or remove metadata.

Prepare reviewed private paths, then inspect without writing:

```powershell
$State = '<ABSOLUTE_PRIVATE_STATE_DIRECTORY>'
$Profile = '<ABSOLUTE_REVIEWED_PROFILE_JSON>'
$Grant = '<ABSOLUTE_REVIEWED_INSTALLED_GRANT_JSON>'
$PublicPin = '<ABSOLUTE_SEPARATE_V2_PUBLIC_KEY_PEM>'
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -File .\Enable-Execution.ps1 -StateDirectory $State -ProfilePath $Profile -GrantPath $Grant -SigningPublicKeyPath $PublicPin -VerifyOnly
```

After owner review, invoke the same command without `-VerifyOnly` to provision.
The owner must first install and protect the reviewed immutable trust assets;
the scripts validate those existing prerequisites without copying or protecting them.
Provisioning preserves a service descriptor when applicable existing read grants
already cover the virtual service account through its SID, Everyone,
Authenticated Users or SERVICE. This conservative no-op proof applies only to
service-status query; channel-read grants remain explicit for the exact service
SID. It rejects ambiguous denies and unsupported/inherit-only access proofs.
Protected services such as Sysmon retain their protection and descriptor. If a
service still needs a DACL change, unknown protection state or any protected
launch level refuses it before the provisioning journal or Agent stop. Recovery
also checks pending service writes before stopping; the native setter rechecks
protection on its own handle. Existing explicit-grant journals remain valid.
The scripts preserve prior descriptors
and fail closed on denies or conflicting changes. They do not grant Security-log,
clear/config/start-stop access or broad group membership. The service retains
Automatic (Delayed Start).

`execution-validate` success means configuration validation only. Its closed result
reports `service_readiness: "not_evaluated"`; an administrator result cannot prove
service-SID access or Ready. Fresh service-local readiness, independent presence
and Manager worker/source health are all required before preview/approval.

## Start the registered Manager worker

Protect `/etc/aegis-manager/manager.env` as root-owned, readable only by the Manager
service group. Configure the separate `AEGIS_MANAGER_EXECUTION_SIGNING_KEY` and
explicitly replace the unit's legacy default arguments with the reviewed registration:

```ini
AEGIS_MANAGER_EXECUTION_SIGNING_KEY=<ABSOLUTE_PRIVATE_V2_SIGNING_KEY>
AEGIS_MANAGER_WORKER_ARGS="--execution-connection <REGISTERED_UUID> --execution-revision <REGISTERED_REVISION> --output-root <EXACT_REGISTERED_OUTPUT_ROOT>"
```

Install/review the shipped `aegis-manager-worker.service`, then use the approved
service-management procedure to enable it at boot and start it. Verify running
identity, independent health refresh, exclusive worker lock, stop/restart and boot
behavior. The configured mode collects **v2 only** for that exact source/revision;
the default `--config` mode collects legacy only. Do not mix both argument families.
One worker/output lock remains authoritative; restart does not reclaim interrupted
collections automatically. The native CI worker gate records actual systemd
start/stop/restart and health/lock results; owner reboot validation remains pending.

## Run, inspect and recover

Use the Manager preview to inspect frozen identity, parameters, pins and collection
window. Approve only the reviewed job while its preview remains valid. Receipts,
health and exit 0 are operational observations. They never become detection events
or a completeness declaration. Inspect the canonical evidence report and actual
evidence IDs before drawing security conclusions:
`execution_receipt_is_detection_evidence: false`, `run_binding: unknown`,
`collection_assurance: unknown`. Missing detection without collection assurance
remains Inconclusive; it cannot establish a false negative or Regression Passed.

Returning to Tác vụ or reloading retrieves the current signed-in actor's latest
approved v2 job from the Manager and continues polling its authoritative status.
Discovery repeats while the page is open, including when an earlier request is
still committing. It does not approve work. The browser stores neither reports
nor approval inputs across logout/reload. If an approval response is lost while
the page remains open, use **Kiểm tra phê duyệt đã gửi** to retry the exact original
approval. This recovery works after preview expiry or busy readiness; it does not
mint a new approval. A permission change discards the local view and retry input.
Never-leased cancellation/expiry releases admission; leased uncertain work and
outstanding collection remain blocked until the server's reviewed lifecycle or
reconciliation releases them.

The protected execution journal retains at most 64 job records, including every
accepted tombstone. Before polling, the agent reserves three file slots and
2 MiB for a maximum 512 KiB record, its atomic publication temporary file, and
1 MiB bounded output. The complete spool is bounded to 192 files / 128 MiB;
orphan temporary/output files count against those limits and are never evicted.
At saturation the agent stays present and reports `local_not_ready`, without
polling for another lease. The final already admitted attempt can finish using
its process-owned reservation; restart never inherits that reservation or replays
a retained ID. All retained records remain protected. Capacity restoration needs
an explicitly reviewed owner retention policy; this slice provides no automatic
deletion, truncation or retention command. Do not delete tombstones to restore Ready.

Before upgrade/rollback, drain/stop through the installer and inspect
`aegis-agent execution-status --state-dir <PRIVATE_STATE>`. This is a point-in-time
observation, not an upgrade lock. Keep SCM stopped through promotion. Preserve
UUID/generation/key/certificate, original 0.1/0.2 creation versions, every journal
entry/log and accepted unknown tombstone. Never restore an older whole-state copy
over newer journal bytes or re-enroll to clear recovery.

After a Manager collection interruption, review the retained job/output and use
the existing explicit `manager_worker --recover-interrupted --output-root
<EXACT_REGISTERED_OUTPUT_ROOT>` procedure to mark interrupted collection failed.
Unknown execution needs owner reconciliation with reasons/evidence; a restart or
elapsed time cannot prove cleanup. Conflicting provisioning/upgrade metadata requires
owner review before retry. Rollback preserves identity/journal and reconciles only
transaction-owned changes; uninstall preserves them too.

Required release artifacts record exact source commit, run URL, actual category
counts/failures/skips and missing prerequisites. Generated SCM/channel fixtures
prove only disposable fixture behavior. Genuine vendor readiness, real SCN-001
canonical Wazuh evidence, ambient-host coverage and reboot-before-login/no-replay
remain separate authorized lab gates. Human/evidence review and lab validation
must complete before merge or rollout.
