# Wazuh Indexer collector — Issue #11

Merged in PR #29 (2026-09-19) and used by Operations Collections; live lab reads on
Wazuh 4.14.4 are recorded below. Issue #11 closed 2026-09-27 with the limits in the
last section.
The Windows fixture parsers remain the mapping authority. No new dependencies.

## Setup

Use a read-only Indexer principal restricted to the approved alert indices and
search/scroll/clear-scroll operations. Do not use the Manager API credentials or
an administrator account. An operator must verify the effective permissions;
the client cannot determine least privilege from a successful search alone.

Set these variables in the process running AEGIS using a local secret store or
PowerShell session. Do not paste their values into chat or commit them:

- `WAZUH_INDEXER_URL`: HTTPS origin, no embedded credentials/path/query.
- `WAZUH_INDEXER_USERNAME`, `WAZUH_INDEXER_PASSWORD`: read-only principal.
- `WAZUH_INDEXER_CA_FILE`: optional local CA bundle; otherwise system trust.

TLS certificate and hostname verification are always enabled. No insecure switch,
redirects or ambient proxy are accepted. `.env.example` documents names but `.env`
files are not automatically loaded. This collector does not probe network addresses.

## Collection

Run from the repository root in the project venv. Replace angle-bracket placeholders
with operator-reviewed local values (they are not literal command arguments):

```powershell
.\.venv\Scripts\python.exe -m aegis_verify.connectors.wazuh.live `
  --index '<approved-index-pattern>' --agent '<agent-id>' `
  --start '<UTC-start>' --end '<UTC-end>' `
  --environment '<environment-id>' --collection-mode direct `
  --output '<private-parent>\new-collection'
```

The parent directory must already exist and be accessible only to the operator.
On Windows, enforce the parent ACL before collecting. The output directory must
not exist. The collector applies and checks an owner-only ACL on each new output
directory before writing evidence, including on Python 3.13. No files are
overwritten. Do not place unreviewed evidence in tracked
directories; use a private location or the ignored `raw-evidence/` directory.

`direct` is an explicit operator statement about topology. Use `forwarded` or
the default `unknown` when direct collection is not established. Missing canonical
fields remain null. This command collects data; it never executes a scenario.

The query uses agent ID and Wazuh ingestion `timestamp`, with inclusive start and
exclusive end. It filters the three supported provider/channel/event-ID combinations:
Security 4688, Sysmon 1 and PowerShell 4104. It does not filter on the expected
detection rule. This is not a query for all Wazuh event types. Review index mappings
and clock/ingestion delay when choosing the window; canonical event timestamps still
come from the original Windows event field, without changing the time basis.

## Output and integration

### Adaptive overflow collection

Add `--adaptive` to collect a fixed operator-selected interval as separate bounded
collections. Only `record_limit` causes bisection. Changed totals, authentication,
TLS, parsing, or failed cleanup of an overflow attempt stop the batch immediately.
Boundaries retain nanosecond precision and use inclusive start/exclusive end, so
adjacent successful leaves have no time gaps or overlaps. Limits are 63 attempts,
12 split levels, a minimum one-second child interval, and a 600-second budget
checked before each collection (an in-flight collection can extend that budget).
Events concentrated at a single timestamp may still exceed the limit; this fails
explicitly instead of dropping events or raising the intake limit.

Each `attempt-NNNN/` retains its evidence. Overflow parent attempts retain
`INCOMPLETE` and must not be evaluated. `batch.json` is published only after all
leaves complete, lists only successful leaves and their collection-manifest hashes,
and is NOT an intake manifest. Evaluate individual nonempty leaves with reviewed
context/profile; do not concatenate them into an oversized intake bundle.
Each leaf has its own snapshot; the entire batch is not one atomic snapshot and
late-arriving or updated data may differ between attempts. Assurance stays unknown.
Existing output directories are rejected. This is not automatic checkpoint resume:
to continue an earlier run, explicitly select the missing interval and a new output
directory, keeping all previous evidence untouched.

- `response-NNNN.json`: exact UTF-8 response bytes, including original unknown fields.
- `hit-NNNNNN.json`: JSON serialization derivatives of individual search hits.
- `collection.json`: response/derivative hashes, JSON pointers linking each derivative
  to its original response, query scope, record count and cleanup status.
- `canonical.json`: canonical v2 events from the same parsers used by fixtures.
- `inputs.json`: existing intake manifest; emitted only after successful nonempty
  collection. An empty collection writes diagnostic output, not an evaluable bundle.
- `INCOMPLETE`: retained on failed collection. Never evaluate that directory.

Canonical evidence IDs/hash/ref identify the derivative bytes, not the original HTTP
response. `collection.json` preserves the additional chain back to raw response bytes.
Serialization is declared as a transformation; it is not claimed to be sanitization.
Treat every output as sensitive. Raw responses can contain scroll IDs and lab values.

To evaluate a complete nonempty collection, supply a separately reviewed `profile.json`
and `context.json` alongside `inputs.json`, then use the existing `aegis validate`
command as described in `CLI_VALIDATE.md`. These are not generated or approved by the
collector. Query completeness does not prove collection completeness; assurance remains
unknown. A successful empty search never becomes False negative or Missing telemetry
without the engine's own required evidence and reviewed context.

## Bounds and failures

Default page size 20; maximum 100 records, 100 pages, 256 KiB per response, 16 MiB
aggregate response bytes, 10-second socket timeout and a 300-second collection budget
checked between pages. A final in-flight request/retry can extend that budget.
The record limit matches the intake manifest's 100-file limit. Narrow the window if
any limit is reached; no partial data is published as a successful collection.

Scroll snapshots keep the query stable while pages are fetched. Every response must
have exact totals, no timeout, all shards successful and no repeated document identity.
Unsupported records, malformed pages and out-of-scope records abort collection.
429 responses permit at most two bounded retries; long/non-numeric Retry-After aborts.
Lost scroll responses are not replayed because replay can skip data. Authentication,
permission, redirect, TLS and connection errors produce fixed codes, never raw responses.

Clear-scroll releases only this collector's search context; it does not delete events.
It runs on success and failure when a cursor is known. Failed cleanup is reported on
success; contexts also expire after one minute. Failed collections retain INCOMPLETE
and their available response bytes for local investigation.

## Lab checklist and teardown

1. Confirm the Indexer version, trusted CA/hostname and read-only principal locally.
2. Select an approved Windows agent and a short window with known existing telemetry.
3. Collect; compare record count with the same Indexer query and trace IDs/hashes back
   through collection.json. Verify all supported profile mappings against source values.
4. Verify an empty window and an intentionally invalid local credential fail/report
   safely. Do not trigger attacks or change rules to perform connection validation.
5. Stop the command; remove credentials from that process session, revoke temporary
   access if used, and retain/delete private evidence according to operator policy.
   There is no daemon or scheduled ingestion to disable.

Tests are offline: `python -m pytest backend/tests/test_wazuh_live.py -q`.
Passing tests are not proof of live reachability or effective server permissions.

Local verification, 2026-09-19: full backend run 2611 passed / 1 skipped
(Windows FIFO unsupported). After adding truncated-response redaction and its
regression checks, the focused collector suite passed 34 tests. Wheel build and
pip check passed; wheel contains the new module. That initial verification was
offline. Subsequent operator-run lab collection used a read-only principal over a
CA/hostname-verified SSH tunnel. The first collection's six Security 4688 events
passed local hash/pointer checks and canonical parser replay. Ten subsequent
completed intervals contained 46 Security 4688, one Sysmon 1 and one PowerShell
4104 event; all 48 passed the same checks. The next interval exceeded 100 records
and remained INCOMPLETE. Private evidence stays outside Git; these observations
are not a detection verdict or proof of least-privilege permissions.

The subsequent operator-run adaptive lab collection completed the missing five
minutes: nine attempts produced five successful leaves containing 0, 68, 87, 1,
and 1 records. Four overflow attempts were retained as INCOMPLETE and excluded.
All 157 new Security 4688 records passed response/derivative/manifest hash checks,
pointer tracing and canonical parser replay. Successful leaf windows were
contiguous, with no duplicate index/document identities within or across the
previous ten intervals. Combined result: 205 records (203 Security 4688, one
Sysmon 1, one PowerShell 4104). No ground truth, detection rule or VM configuration
was changed by this collector.

Adaptive verification, 2026-09-19: 49 focused live/adaptive tests passed;
full backend suite 2629 passed / 1 skipped (Windows FIFO unsupported), using
a fresh explicit pytest base directory to avoid the shared Windows temp-dir ACL
cleanup error. `pip check` passed. Independent bounded adaptive review reported
no Critical/Important findings. Follow-up fixes now map collection-manifest read
failures to `output_error`; tests cover nonempty split boundaries, retention of
completed evidence after a later failure, successful bounded rate-limit retry,
invalid Retry-After and response-size rejection.

## Acceptance and review checklist

Final local review verification, 2026-09-19: full backend suite **2638 passed,
1 skipped** (Windows FIFO unsupported), wheel build and `pip check` passed.
Independent follow-up review found no remaining Critical/Important findings.
Private lab evidence was not copied into this checkout. No commit, push, issue
closure or merge was performed during this review pass.

| Issue #11 criterion | Evidence / implementation |
| --- | --- |
| Configured approved interface | Indexer HTTPS origin and index scope in Config/environment |
| Read-only credentials | Environment input; only search/scroll/clear-scroll routes; operator must separately audit effective role mappings |
| TLS verification | CA and hostname verification required, no insecure flag; lab tunnel used certificate-valid loopback endpoint |
| No secret/raw-response logging | Fixed diagnostic codes, redacted exception tests; raw bytes only in private evidence files |
| Pagination/time/retries/errors | Exact totals, scope checks, bounded scroll, 429 handling, adaptive overflow; unit and live lab checks |
| Canonical equivalence | Existing fixture parsers; three profile contract tests and private lab replay |
| Setup/teardown | Sections above; stop CLI/tunnel and remove process credentials when finished |
| Existing tests | See local verification record; rerun with a fresh pytest base directory whose parent exists |

Known limits at closing (2026-09-27): least-privilege role mappings were reviewed
by the operator in the Indexer UI, not audited automatically. Only HTTP 429 is
retried (at most twice, Retry-After capped at 10 s); 5xx and connection errors are
not retried because replaying a scroll could skip data. Successful reads alone do not establish
that the account lacks unrelated permissions. Live invalid-credential/rate-limit
failure injection was not performed; those paths were tested offline.

References: Wazuh Indexer API reference and OpenSearch Scroll API documentation linked
from `ISSUE_11_CONNECTION_DESIGN.md`. Live protocol compatibility remains a lab gate.
