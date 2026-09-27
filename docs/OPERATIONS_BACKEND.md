# Local operations backend (issue #36)

This opt-in backend is not the completed operations UI. Inventory is added by
issue #37; UI and launcher integration follow separately. Collection never evaluates a
scenario or creates a security verdict. Default dashboard behavior stays read-only.

## Local configuration

Prepare an existing owner-only evidence directory **outside** the checkout,
report directory and static assets. POSIX requires current owner and mode 0700;
Windows requires current-user ownership and only current-user allow ACEs, including
inheritable FullControl for files and subdirectories. The backend checks the
existing root and child ACLs. Newly created job and collection directories receive
an owner-only ACL before evidence is written; existing ACLs are never repaired or
loosened. This is needed on Windows Python 3.13, where mkdir mode 0700 also grants
Administrators/SYSTEM access. Run it as the operator, not as a different privileged user.
Elevated Windows sessions whose default object owner is Administrators are not
supported: new child objects fail the current-user ownership check. Use a normal
non-elevated operator session; do not loosen the ACL check to work around this.

Create a private JSON file (replace the illustrative local paths and endpoint):

```json
{
  "version": 1,
  "environment_id": "training",
  "agent_ids": ["configured-agent-id"],
  "index": "wazuh-alerts-*",
  "output_root": "C:/AEGIS-private/evidence",
  "indexer": {
    "endpoint": "https://indexer.example.test",
    "ca_file": "C:/AEGIS-private/root-ca.pem"
  }
}
```

Set `WAZUH_INDEXER_USERNAME` and `WAZUH_INDEXER_PASSWORD` in the process that
starts the backend; do not place them in JSON or the command line. Use a private
local credential prompt, never send the password in chat. Missing credentials
disable collection. TLS remains verified; no insecure option is provided.

```powershell
& .venv/Scripts/python.exe -m aegis_verify dashboard --reports C:/AEGIS-reviewed/reports --static frontend/dist --operations-config C:/AEGIS-private/operations.json
```

Do not use a network share, symlink, junction, mapped provider syntax, traversal
or an output folder within source/reports/static. Bind remains `127.0.0.1` only.
Indexer credentials do not grant Server API access. To opt into inventory, add a
`server_api` object with its own `endpoint` and `ca_file`, and provide
`WAZUH_API_USERNAME` and `WAZUH_API_PASSWORD` to the backend process. Never reuse
Indexer credentials implicitly. The Server API identity needs `agent:read` for
the configured allowlist, not administrative rights. Protocol is checked against
the [Wazuh v4.14.4 API specification](https://github.com/wazuh/wazuh/blob/v4.14.4/api/api/spec/spec.yaml).

Inventory is administrative metadata, not canonical security evidence. GET
`/api/operations/agents` never contacts Wazuh; POST `/api/operations/agents/refresh`
with `{}` requests one bounded refresh. Only configured agents are requested.
Authentication tokens remain in memory. Refreshes have a 30-second cooldown,
50-item pages, ten-page limit, 1 MiB response limit and 5 MiB cumulative limit.
The adapter checks a 60-second deadline before and after requests; a blocking
socket read may finish later (10-second socket timeout), but late results are
not published. One expired-token reauthentication is permitted per refresh.

Snapshots older than 60 seconds or retained after a refresh failure are `stale`.
Missing/duplicate agents or partial pages reject the whole refresh; the last
complete snapshot remains visible. Source status and source keepalive are kept
separate from fetch time. Failure never turns an agent into `disconnected`.
Wazuh pagination is not an atomic point-in-time snapshot: status can change
between valid pages. Membership checks cannot detect every such source change.
Unconfigured inventory does not disable collection, and vice versa.

## Request boundary

Routes under `/api/operations/` require exact Host and `X-Aegis-Client:
operations-v1`. GET bootstrap supplies a process-session token, then requests
require `X-Aegis-Session`. POST additionally requires exact Origin and
`Content-Type: application/json`; body limit is 8 KiB. No CORS, URL credentials,
shell commands, raw query DSL or raw evidence download routes exist.

Collection submission fields are `agent_id`, explicit UTC `start`/`end`, boolean
`adaptive` and UUID `request_id`. The window must be at most 24 hours and end no
later than the server clock. One job runs at a time, without a queue. Retry the
same ID only for the identical input; do not automatically resubmit a failed job.

## Recovery and limits

- Keep the process running until the job finishes. Ctrl+C stops admission and
  drains the bounded collector; this can take time. Forced termination may leave
  an incomplete bundle and marks running metadata interrupted at next startup.
- 0 records is a completed empty query, not proof of missing detection.
- Cleanup failure is visible separately. Incomplete results are never successful.
- At most 100 persisted jobs and at least 2 GiB free for admission. This does not
  promise sufficient disk space under all conditions; no automatic deletion occurs.
- One process owns an evidence root. A second instance is refused. A root is
  bound to environment/allowlist/index; use a fresh private root when scope changes.
- Corrupt metadata disables submission; preserve it for review. Do not delete
  evidence or edit states to manufacture completion. Crash-left `.pending-*`
  metadata also requires operator review; it is not silently ignored.
- Completed bundles remain private. Review collection completeness and use the
  existing explicit evaluation workflow to generate reviewed dashboard reports.

Fixture tests are not live-lab acceptance. No release/tag or permission change is
authorized by enabling this option.

### Operator recovery checklist

1. **Source or SSH tunnel unavailable:** retain the current evidence root. Check
   the configured tunnel and TLS trust locally without disabling verification.
   Inventory `stale` means the displayed source status is from an older snapshot;
   `unavailable` means no successful snapshot exists in this process. Neither
   means the endpoint itself is disconnected. After restoring connectivity, use
   **Refresh inventory** once (respect the 30-second cooldown), then check the
   new fetch time and error status. Restoring a tunnel alone does not refresh it.
2. **Collection failed:** inspect the job's fixed error code and preserve any
   partial bundle. A restored connection does not resume or replay that job.
   Review the target and UTC window before explicitly submitting another job
   with a new request ID. Reusing the old ID returns the existing job, not a retry.
3. **Normal stop:** use Ctrl+C and allow the bounded worker to drain. Do not
   start a second process against that root while the first still owns it.
4. **Process forcibly stopped:** restart with the same reviewed configuration
   and private evidence root. Previously running jobs should become `interrupted`,
   with no automatic collection. Review the retained bundle as potentially
   incomplete, even if it contains files; do not change metadata to `completed`.
5. **Storage recovery blocked:** if metadata is corrupt or `.pending-*` files
   remain, stop and preserve the entire root for review. Make any backup only
   after the writer has stopped, to another owner-only private local directory.
   Do not delete lock/metadata files or move selected files into a live root to
   bypass the safeguard. A new root starts separate history; it is not a repair
   of the old evidence. Keep raw evidence and credentials out of Git and chat.
6. **`disk_space`:** check free space on the volume containing `output_root`,
   not just the source checkout. Admission requires at least 2 GiB. Preserve
   evidence; do not lower the safety threshold to force collection. Before
   choosing a new local output root, verify both available space and owner-only
   ACL support under the actual operator account. A volume can have ample free
   space while refusing the required ACL operations. Changing roots does not
   transfer existing job history or certify a backup.

The P2 fixture checks exercise an actual test-owned process termination, OS
lease release, two fresh recovery processes, unchanged completed metadata and
partial/completed fixture bytes, and no collector replay. Inventory checks cover
source loss both before and after a successful snapshot, followed by explicit
manual recovery. These tests replace source calls with fixtures and bypass ACL
inspection in the recovery subprocess; they do **not** establish live TLS,
Windows ACL correctness, physical power-loss durability, arbitrary crash timing,
backup/restore acceptance, or SCN-001 detection correctness.

### Scope beyond SCN-001

Operations collection remains scoped to SCN-001. SCN-002 (`Prevented`,
2026-09-22) and SCN-003 (`Detected`, 2026-09-26) were validated through
separately exported evidence bundles and the offline CLI, not through
Operations; see their result documents. These recovery tests do not extend
Operations to other scenarios, authorize running a scenario, or change any
scenario ground truth.
