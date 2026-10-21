# AEGIS first-flow protocol 0.1.0

This is a lab prototype contract, not full Manager v1 acceptance. Real credentials, certificates, keys and endpoint addresses are private configuration.

## Transport and identity

Agent opens outbound HTTPS with an OS-trusted Manager hostname and its own client certificate. Redirects and ambient proxies are disabled. Manual owner enrollment records the SHA-256 DER fingerprint, device UUID, environment ID and positive integer generation. Revocation is checked on every request.

For the Linux deployment nginx validates client certificates against the private agent CA. It forwards only `/agent/v1/` to the loopback application and overwrites `X-Aegis-Client-Verify: SUCCESS` and `X-Aegis-Client-Cert` with `$ssl_client_escaped_cert`. Django trusts these only from loopback, only on HTTPS-proxy requests, and derives the SHA-256 fingerprint itself. The app port must bind loopback and the host/VM must not allow untrusted local processes; this trusted-proxy boundary is a first-slice assumption. Other routes cannot use agent certificate headers as human authentication.

## Signed envelope

JSON has exactly `protocol`, `key_id`, `payload`, `signature`. `protocol` is `0.1.0`; `key_id` is `manager-v1`. `payload` and `signature` are standard padded base64. Payload is the exact signed UTF-8 JSON byte sequence. Algorithm is fixed RSA-PSS, SHA-256, MGF1 SHA-256, salt length 32; RSA modulus at least 3072 bits. Verify before parsing the payload. Maximum HTTP document 64 KiB. Duplicate or unknown JSON properties are rejected.

Payload properties (all required; no others):

| Property | Type/constraint |
| --- | --- |
| `protocol` | literal `0.1.0` |
| `job_id`, `run_id`, `agent_id`, `approval_id` | lowercase canonical UUID strings; run_id equals job_id |
| `environment_id` | nonempty ASCII identifier, `[A-Za-z0-9_-]{1,64}` |
| `generation` | integer 1..2147483647 |
| `scenario_id` | literal `SCN-001` |
| `scenario_sha256`, `profile_sha256`, `runner_sha256`, `kit_sha256`, `payload_sha256` | 64 lowercase hexadecimal characters; match the local approved catalog |
| `runner_id` | literal `scn001-safe-demo` |
| `runner_version` | literal `0.3.0` |
| `not_before`, `expires_at`, `collection_start`, `collection_end` | UTC ISO8601 second precision, `YYYY-MM-DDTHH:MM:SSZ` |
| `timeout_seconds` | integer 180..300 |
| `parameters` | object with exactly `run_label`, `rule_revision`, `rule_sha256` |

Parameter values: `run_label` is `A`, `B`, `C` or `Rehearsal`; `rule_revision` is `baseline` or `behavioral`; A/B require baseline and C requires behavioral. `rule_sha256` must equal the locally reviewed revision hash. Rehearsal is allowed only if explicitly selected in the local catalog. Jobs never carry paths or shell strings.

`expires_at - not_before` is positive and at most 300 seconds. Agent starts only within that interval, with no clock-skew grace. `collection_start <= not_before`, `collection_end >= expires_at + timeout_seconds`; total collection duration at most 900 seconds. These are source query bounds declared by the owner, not proof of clock synchronization or collection completeness. The worker waits until collection_end plus configured settle delay. Manager and agent clocks require lab preflight.

## Routes

All requests are POST with `application/json`, except the response to a poll may have no content. Bodies have no unknown or duplicate properties. Identity comes from mTLS, not request body.

- `POST /agent/v1/poll` with `{ "protocol": "0.1.0" }`: returns 200 signed envelope or 204. Claim persists once before response. Subsequent polls return the same unstarted lease; after start they never dispatch it again.
- `POST /agent/v1/jobs/<job_id>/start` with `{ "protocol": "0.1.0", "payload_sha256": "..." }`: 200 `{ "authorized": true }` exactly once for a valid current lease. Any duplicate/uncertain start is 409; the agent must not execute on a missing/non-200 start response. The owner reconciles ambiguous starts. Revoked/cancelled/expired leases fail.
- `POST /agent/v1/jobs/<job_id>/receipt` with the receipt object below: 200 `{ "accepted": true }` on first receipt or byte-equivalent validated retry. Changed receipt is 409. Cross-device submissions fail.

No live running-job cancellation endpoint in this foreground slice. Owner can Ctrl+C the foreground agent; local timeout and Job Object bound execution when Manager is unavailable. Queued jobs can be cancelled in Manager before start. Full service cancellation is a later v1 gate.

## Terminal receipt

Exactly: `protocol`, `receipt_id` (UUID), `job_id`, `payload_sha256` (SHA-256 of signed payload bytes), `state` (`succeeded`, `failed`, `execution_unknown`), `started_at`, `finished_at` (UTC second precision), `exit_code` (integer or null), `cleanup_succeeded` (bool).

`succeeded` requires exit_code 0 and cleanup true. Times must lie within approved start/deadline bounds and finished >= started. Receipt is an authenticated caller report, not a Wazuh event or independent attestation. It never supplies canonical evidence IDs or a detection verdict. Detailed runner output remains private in the agent spool for later study review, not uploaded as detection evidence.

## Journal and recovery

One exclusive spool lock per agent process. Before requesting start, save the verified payload digest and job. After start authorization, atomically persist launch intent before process creation. A durable launch intent without a terminal receipt becomes execution_unknown after restart; never run it again. Persist a terminal receipt before upload and retry the same receipt only. A lost start response never causes execution. Restoring old journals/Manager DB requires owner reconciliation and identity generation change, not normal automatic resume.

## Collection/evaluation

Job execution, collection and engine verdict are separate fields. Worker rechecks release pins, queries the mapped Wazuh agent in the approved window with the existing bounded collector, and calls the existing canonical engine with no completeness declarations. Empty query is `empty`, source/input failure is `failed`, absent alert stays Inconclusive where the engine requires attestation. Reports explicitly retain run binding as unknown; a signed job does not prove event-to-run binding or complete SCN-001 study acceptance.
