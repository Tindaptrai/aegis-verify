# Local operations backend (issue #36)

This opt-in backend is not the completed operations UI. Agents inventory and
launcher integration follow in separate issues. Collection never evaluates a
scenario or creates a security verdict. Default dashboard behavior stays read-only.

## Local configuration

Prepare an existing owner-only evidence directory **outside** the checkout,
report directory and static assets. POSIX requires current owner and mode 0700;
Windows requires current-user ownership and only current-user allow ACEs, including
inheritable FullControl for files and subdirectories. The backend checks ACLs but
does not change them. Run it as the operator, not as a different privileged user.

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
Indexer credentials do not grant Server API access; inventory is not configured
by this backend delivery.

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
