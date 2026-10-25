# Paired Windows execution v2 contract

Issue #161 foundation. These contracts do not enable dispatch, install an adapter,
perform a target handoff, execute a scenario, or upgrade collection assurance.
Legacy execution `0.1.0` and presence/network `2.0`/`2.1` retain their own codecs.

## Wire rules

The execution protocol is `aegis-windows-execution/2`, key ID
`manager-execution-v2`, provider `reviewed-scn001-windows/1`. Scenario/runner/version
are exactly `SCN-001`, `scn001-safe-demo`, `0.3.0`. All object key sets are closed,
including nested objects. Missing keys, duplicates, unknown keys, nonfinite
numbers, bool-as-int and wrong primitive types fail validation.

Requests and decoded signed JSON are at most 65,536 bytes; envelopes at most
98,304 bytes; maximum container depth is 12. UUIDs are nonzero canonical lowercase
hyphenated strings. SHA256 values are lowercase 64 hex characters. Generation and
revisions are positive int32; release IDs positive int64. Timestamps have exactly
UTC second precision, `YYYY-MM-DDTHH:MM:SSZ`. Environments match
`[A-Za-z0-9_-]{1,64}`. Base64 uses canonical RFC4648 spelling with padding and
without whitespace. JSON transport whitespace is allowed within byte limits.

`I` below means `protocol,device_id,generation`; `B` means
`binding_id,binding_revision`. These are field-set unions, without nested wrappers.

| Record | Exact keys |
| --- | --- |
| ReadinessRequest | I + B + installation_profile_sha256,artifact_set_sha256,ready,blocking_codes |
| ReadinessAck | protocol,server_time,accepted |
| PollRequest | I + B |
| Envelope | protocol,key_id,payload,signature |
| SignedJob | I + B + job_id,run_id,certificate_sha256,approval_id,environment_id,release_id,approval_snapshot_sha256,scenario_id,runner_id,runner_version,scenario_sha256,profile_sha256,runner_sha256,kit_sha256,payload_sha256,not_before,expires_at,collection_start,collection_end,timeout_seconds,parameters |
| Parameters | run_label,rule_revision,rule_sha256 |
| StartRequest | I + B + start_request_id,job_sha256 |
| StartAck | protocol,job_id,start_request_id,job_sha256,authorized |
| Receipt | I + B + receipt_id,job_id,job_sha256,state,started_at,finished_at,exit_code,cleanup_succeeded |
| ReceiptAck | protocol,job_id,receipt_id,job_sha256,accepted |

Acknowledgment accepted/authorized fields are literal `true`; `run_id=job_id`.
Labels A/B use baseline; C uses behavioral. Rehearsal requires explicit reviewed
release permission. Selected rule hashes must match the frozen rule pins. Timeout
is 180..300 seconds. Execution expiry is at most 120 seconds after not-before;
collection starts no later than not-before, ends at least timeout seconds after
expiry, and spans no more than 900 seconds. Preview services must derive the exact
approved T0 windows rather than accepting client times.

The human `JobDTO` response alone permits up to 4,194,304 bytes, including its
opaque canonical report. Its depth, finite-number and closed execution-field
rules remain unchanged. This response allowance does not widen any human or
machine request, decoded signed payload, envelope, or other execution record.

Receipt states are `succeeded,failed,execution_unknown`. Nullable start and int32
exit code preserve unobserved values; cleanup is a strict bool. Observed start
cannot follow finish. Succeeded requires observed start, exit zero and cleanup
true. Failed requires observed start. Unknown may have no start, including a
previously leased cancelled/expired job; the service checks lifecycle context.

Local blocking reasons are `profile_mismatch,artifact_mismatch,clock_uncertain,
local_not_ready,unsupported_platform`. Reasons are distinct, at most eight, and
ready requires an empty list. The public vocabulary additionally contains
`upgrade_required,binding_missing,binding_disabled,identity_unavailable,
environment_invalid,mapping_missing,ownership_conflict,local_stale,
worker_unavailable,source_unavailable,busy,reconciliation_required`.

## Frozen approval authority

Canonical hashing uses UTF-8 JSON, sorted keys, compact separators, ASCII escaping
and no NaN. Signature verification always covers original payload bytes, without
canonicalizing or reserializing them. RSA3072-or-stronger PSS-SHA256 uses salt32.
`job_sha256` hashes raw signed JSON; inner `payload_sha256` pins the script.

Set `AEGIS_MANAGER_EXECUTION_SIGNING_KEY` to a separately provisioned private key.
The setting is optional until execution is configured, keeping v1 startup intact.
The signing code rejects key reuse with the configured v1 or enrollment CA key,
including copies at different paths. When PRIVATE_ROOT is configured the new key
must be inside it. Existing v1 signing code and signed history are unchanged.

`ReleaseDefinition` has exactly:

```
release_id,scenario_id,runner_id,runner_version,artifact_pins,rule_pins,
allow_rehearsal,timeout_seconds,evaluation_bindings,scenario_path,profile_path
```

`DeviceExecutionBinding.release_bytes` stores its canonical bytes;
`release_sha256=SHA256(release_bytes)`. The definition contains neither its own
digest nor per-job parameters. `SnapshotRelease` adds `release_sha256,parameters`
to that exact definition. Its decoder verifies the digest against the definition
and checks parameters against reviewed rules/permission. A/B/C can therefore
share one binding/release digest while approval snapshot and job hashes differ.

`JobApprovalSnapshotData` schema version 1 has exact keys
`schema_version,identity,binding,release,windows,connection`:

| Nested record | Exact keys |
| --- | --- |
| identity | device_id,generation,certificate_sha256,environment_id |
| binding | binding_id,binding_revision,provider_id,installation_profile_sha256,artifact_set_sha256,ownership_revision |
| release | ReleaseDefinition + release_sha256,parameters |
| windows | not_before,expires_at,collection_start,collection_end |
| connection | connection_id,revision,config_path,config_sha256,output_root_fingerprint,wazuh_agent_id |
| ArtifactPins | scenario_sha256,profile_sha256,runner_sha256,kit_sha256,payload_sha256 |
| RulePins | baseline,behavioral |
| evaluation binding | name,value |

Evaluation bindings reuse the existing engine contract: nonblank bounded names,
strict string/int values or bounded homogeneous string/int lists. Frozen private
scenario/profile references are verified by their pins by consuming services;
the mutable RunnerRelease FK supplies provenance, never approval authority.

## Human DTOs

These belong to the `/api/v1/execution` route contract; existing inventory DTOs do
not gain fields. Absent readiness metadata is null. Capability is one of
`installed_supported,upgrade_required,unsupported`, independent of ready.

| Record | Exact keys |
| --- | --- |
| ExecutionDeviceDTO | device_id,provider_id,binding_id,binding_revision,capability,ready,blocking_codes,checked_at,readiness_expires_at,release_id,release_sha256,wazuh_connection_id,wazuh_agent_id |
| BindingInput | expected_revision,enabled,provider_id,runner_release_id,installation_profile_sha256,wazuh_connection_id,wazuh_connection_revision,wazuh_agent_id |
| PreviewInput | device_id,provider_id,binding_revision,run_label,rule_revision |
| ApproveInput | preview_id,preview_sha256,idempotency_key |
| PreviewDTO | preview_id,preview_sha256,expires_at,summary |
| PublicSummary | device_id,environment_id,wazuh_connection_id,wazuh_agent_id,provider_id,binding_id,binding_revision,release_id,release_sha256,scenario_id,runner_id,runner_version,parameters,timeout_seconds,not_before,expires_at,collection_start,collection_end,artifact_pins,rule_pins,cleanup_policy,execution_receipt_is_detection_evidence,run_binding,collection_assurance |
| JobDTO | job_id,summary,execution_state,collection_state,evaluation_state,created_at,started_authorized_at,finished_at,error_code,report |
| ProviderDTO | provider_id,scenario_id,runner_id,runner_version,release_id,release_sha256,allow_rehearsal,timeout_seconds |
| ProviderList | providers |

ProviderList.providers is an array. BindingInput.expected_revision is null only
for initial revision (service enforces current revision). `cleanup_policy` is
`bounded_process_tree`. `execution_receipt_is_detection_evidence=false`,
`run_binding=unknown`, `collection_assurance=unknown` are constants. Private
connection path/config digest and private file paths never enter PublicSummary.
Evaluation state is `not_evaluated,evaluated`; the report remains the unchanged
canonical JSON object or null, recursively frozen on decode within the separate
4 MiB JobDTO response limit. Collection states
remain pending/collecting/evaluated/empty/failed/reconciled. Receipt and health
never manufacture detection evidence or declare collection complete.

Machine errors have exactly `{error:{code}}`: invalid_request400,
identity_denied403, job_not_found404, lease_conflict/start_conflict/receipt_conflict409,
temporarily_unavailable503. Human routes keep their existing authentication errors
and add preview_conflict/job_conflict/binding_conflict409, execution_unavailable503.
Exception values are never response text. Render reason codes as translated copy.

## Storage and consuming interfaces

`DeviceExecutionBinding` and `RegisteredExecutionConnection` have internal bigint
PKs and public UUID (`binding_id`/`connection_id`) plus positive monotonic revision.
Bindings have a conditional unique current row per Device (`is_current`) and
immutable identity/mapping/release/profile/artifact fields within each revision.
Retire a current revision through an is_current-only queryset update.
`binding.set_enabled(bool, actor)` audits admission changes separately in
BindingAdmissionAudit; direct enabled updates are rejected.

Snapshots, preview ownership, idempotency and audit records reject mutation and
deletion through save/queryset/bulk-update/upsert/admin paths. Canonical snapshot
bytes and hash are checked at insertion. `ExecutionPreview.snapshot` is a
OneToOne reference to JobApprovalSnapshot, the single source of its bytes/hash.
Job.preview is OneToOne, enforcing at most one job per preview. Preview and
idempotency actor references bind the user PK, never a mutable username.

Ownership resource uniqueness is `(connection_id,environment_id,wazuh_agent_id)`.
`record_transfer(actor,expected_revision,reviewed_legacy_device_id,
reviewed_paired_device_id,active_executor_id)` is an atomic audited persistence
primitive; callers must first enforce permissions, DispatchLock and idle target
fences. It does not authorize or execute a real handoff. Direct update/save of
existing ownership is rejected. ExecutionOwnershipAudit is append-only.

Job.protocol_family defaults to `legacy_v1`; new jobs use
`windows_execution_v2`. V1 rows retain null binding/approval_snapshot/preview and
raw-byte fields. New binary fields are `envelope_bytes,signed_payload_bytes,
start_request_bytes,start_ack_bytes,terminal_receipt_bytes,receipt_ack_bytes`.
Digest/identity columns are `job_sha256,start_request_id,start_request_sha256,
terminal_receipt_id`; receipt identity is globally unique when nonnull. Once a v2
authority field is populated it cannot be rewritten, including bulk upsert paths.
LocalExecutionReadiness is a latest report, and CollectionWorkerLease pins private
instance/connection revision/config/output-root/source probe metadata. Neither is
a durable collecting claim. Source collection admission and lifecycle services
remain separate tasks.

Python interfaces are `parse_execution_request(kind,raw)`,
`decode_contract(record_name,raw)`, `snapshot_bytes(snapshot)`,
`release_definition_bytes(definition)`, `freeze_release(definition,parameters)`,
`public_summary(snapshot)`, `sign_execution_payload(payload)` and
`verify_execution_envelope(raw,public_key)`. Request kinds are
readiness/poll/start/receipt/binding/preview/approve. Decoders return frozen typed
records; signing returns `(envelope_bytes,job_sha256)`.

C# interfaces live in `Aegis.Connection.Execution`, independently from Protocol.
`ExecutionProtocol.Verify(envelope,key,grant,now)` validates signature, paired
identity/certificate/time/binding, installed profile/artifact hashes, rules and
permission. PublicKeySha256 is the separately provisioned SHA256 of SPKI DER.
ExecutionGrant combines validated InstallationProfile, InstalledGrant and paired
IdentityState in memory; no polymorphic wire grant or Manager-provided key exists.
VerifiedExecutionJob exposes Job, JobSha256 and defensive copies of EnvelopeBytes
and PayloadBytes. CanonicalBytes preserves Python ASCII escaping (including
apostrophe/plus/ampersand path characters). Request serializers are
SerializeReadiness/SerializePoll/SerializeStart/SerializeReceipt; ack decoders
are ReadinessAck/StartAck/ReceiptAck. Blocking code arrays are immutable.

InstallationProfile exact keys are `schema_version,provider_id,environment_id,
expected_computer_name,scenario_path,profile_path,runner_path,kit_directory,
run_directory,study_path,study_sha256,artifact_pins,rule_pins,allow_rehearsal,
timeout_seconds`. InstalledGrant exact keys are `schema_version,device_id,
generation,certificate_sha256,binding_id,binding_revision,
installation_profile_sha256,artifact_set_sha256`. Both use schema_version1.
Artifact-set bytes are canonical `{artifact_pins:ArtifactPins,rule_pins:RulePins}`.
Installation profile hash covers its canonical closed record, excluding binding
association. File/path/host/ACL/policy checks and actual artifact reads belong to
local preflight; these codecs do not claim local or remote readiness themselves.

Cross-language test harness `--execution-vector <temporary-directory>` accepts
only generated public verification material and invokes production Verify. It
never executes payloads or reads private signing keys. Build the connection tests
first; AEGIS_CONNECTION_TEST_EXE may select a published harness binary. Generated
test keys/certificates remain temporary and are never committed.

## Local readiness and private worker integration

The supported execution build is exactly paired Windows x64 agent `0.3.0`.
The version is only a capability gate: current enabled binding, verified identity,
matching installed grant/profile/actual artifact hashes, reviewed mapping and
ownership, fresh local presence/report and private worker/source health are all
required. Linux remains presence-only. Execution rejects legacy environment
syntax containing dots without changing the enrolled environment. Public DTOs
show at most eight distinct blocking codes; further failures become visible as
earlier failures are resolved. A readiness acknowledgment accepts a report, not
its claim of Ready. Local reports/presence and worker leases expire beyond30s;
successful source probes expire beyond60s, including during slow source I/O.

Connection registration is a local service operation requiring fresh
`manage_connections`, AccountMutationLock then DispatchLock, and global idle:
`register_execution_connection(actor, *, connection_id=None, expected_revision,
config_path, output_root)`. Initial ID/revision are both null; updates require an
explicit existing ID and expected current revision. Revisions are append-only.
Migration0008 adds private `output_root_path`; historical blank paths fail closed
until an explicitly reviewed new revision. Resolution uses exact ID/revision and
rechecks protected config bytes and the validated output-root fingerprint
`SHA256(os.path.normcase(str(root)).encode())`. Neither path nor hash is public.

The worker's optional `--execution-connection <uuid> --execution-revision <int>`
selects registration identity; it cannot be combined with `--config`.
`--output-root` must match the registered private root. While holding the existing
OS worker lock, independent keepalive and source loops run; keepalive refreshes
every5s and never advances source success time. All current enabled reviewed
binding scopes for that exact revision must pass one <=50s bounded source round.
The probe uses the existing verified HTTPS transport, a non-scroll size0 search,
and rejects failed/incomplete/timed-out shards. Zero hits can be healthy. No
binding scope, unknown status, drift or failed round blocks execution. Restart
does not reclaim durable `collecting` state. The explicit v2 collection call is
`process_one(connection, root, settle_seconds=..., execution_connection=registered)`;
until the Task5 dispatcher implements that kwarg the configured v2 worker stops
closed. Legacy positional collection calls retain their existing behavior.

Local loading uses explicit
`ExecutionProfile.Load(profilePath, grantPath, signingPublicKeyPath, identity)`;
there is no sibling/path/key discovery or key from a wire response. Active assets
must be immutable to the service identity and ordinary users. Writable identity
ACL helpers do not establish executable-cache trust. `LoadSigningKey(path,grant)`
returns a caller-owned RSA handle only after checking that same protected file and
SHA256(SPKI DER) pin. `Check(grant)` reads actual artifacts and the per-device
study/kit; `CheckBeforeLaunch(job,grant,clock,nowMonotonic)` repeats checks and
requires the entire time interval inside `[not_before,expires_at)`.

This built-in provider accepts only raw SCN-001 0.1.0 Git-blob scenario bytes:
887 LF bytes, SHA256
`4f00335ddd0e39979d90852122642b945faa03ba50d7e9189fe282662bad84a9`.
The actual bytes must match both this supported hash and the reviewed grant.
The current Windows checkout may be CRLF because the scenario has no EOL
attribute; provision the canonical Git blob rather than silently converting at
runtime. No scenario ground truth is edited. Existing Python `verify_study`
validates YAML/fingerprint and profile semantics during reviewed per-device
provisioning. Managed preflight checks the fixed supported raw scenario, closed
study/kit records, native/canonical paths, exact ASCII/LF payload, all kit asset
pins and the reviewed assertion predicates/correlation; health does not verify
remote rule application.

Native preflight reads only service status and the two enabled Operational
channels with prior Sysmon1/PowerShell4104, under `NT SERVICE\AegisAgent`, and
checks Windows/x64/PowerShell5.1. It changes no service, ACL, channel or policy.
Effective execution-policy proof is deliberately unknown in Task3's native
facts implementation, so it returns `local_not_ready`. Task4 must complete the
contained native policy proof seam; no uncontained helper or permissive fallback
is supplied, and this intermediate build cannot honestly advertise local Ready.

`ExecutionClock` is thread-safe. `MonotonicNow` is a TimeSpan from a private
Stopwatch origin; the same clock instance supplies exchange timestamps and launch
checks. `Observe(serverTime,sentUtc,sentMonotonic,receivedMonotonic)` is only for a
decoded authenticated acknowledgment. The second-precision server interval and
measured round trip bound absolute offset; uncertainty then grows by the *full*
elapsed monotonic duration plus the largest observed UTC/monotonic discrepancy.
No oscillator drift assumption is made. Bound >5s, age >15s, negative/out-of-order
monotonic input or clock jumps fail closed; a jump cannot be forgotten without a
new authenticated observation. `TryGetBounds(now,out ExecutionTimeBounds)` and
`IsCertain(now)` use the same interval. Certainty is intentionally short, so
Task4 must refresh immediately before lease/start/native creation when needed
and republish readiness after the initial clock acknowledgment. No NTP changes
or physical metrology claims are implied. Readiness/probe/receipt creates no
events, completeness declaration, evidence conclusion or assurance upgrade.
