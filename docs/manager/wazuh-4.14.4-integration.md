# Wazuh 4.14.4 self-managed integration

| Metadata | Value |
| --- | --- |
| vendor / product | Wazuh / Indexer |
| version_range / deployment | 4.14.4 / self-managed |
| connector_release / guide_revision | unreleased (issue #163; connections API v1) / 1 |
| reviewed_at | 2026-10-29 |
| validation_status | docs-reviewed; native lab acceptance pending |
| screenshot_provenance | unavailable |

**Chưa có ảnh kiểm chứng.** No genuine sanitized Wazuh 4.14.4 screenshots are
available for any step. This guide supplies text instructions, not simulated
vendor screenshots. Upstream current/latest references support design review;
they do not establish the effective permission expansion or compatibility of a
particular 4.14.4 installation. The version is a selected integration contract,
not server-version discovery. Other versions/deployments remain unverified.

## 1. Confirm the service and prerequisites

AEGIS reads the **Indexer HTTPS data API**, not the Dashboard URL or the Server
API for agent administration. Have the Wazuh administrator confirm the reviewed
index scope, technical account, HTTP public CA, certificate SAN and route from
Manager. Do not supply administrator credentials to AEGIS.

Before changes on Wazuh, obtain approval, back up configuration and role mappings,
and agree on rollback. Firewall or permissions changes are administrative changes,
not actions that the Manager form performs. Restrict the network path to Manager
and the reviewed Indexer port. Do not change cluster transport TLS for this form.

New managed source storage requires Linux Manager. A root administrator installs
the endpoint policy outside the checkout/private storage. It pins the exact HTTPS
origin, port, addresses and index. Missing/invalid policy fails closed for new
onboarding; legacy registrations remain unchanged. New policy accepts explicitly
pinned private/global IPv4 and globally routable IPv6 after prohibited-address
checks. CGNAT and IPv6 ULA are unsupported. DNS, TLS chain and SAN remain checked;
the form cannot edit the policy or bypass verification.

For release backup/migration, one-time policy provisioning, the exact nginx
upload route, separate waiting service, cleanup and rollback, follow the
[managed connections deployment handoff](managed-connections-deployment.md).
Installing a waiting service does not activate a source or prove source health.

Elastic remains **offline only**. Splunk remains **planned**. This guide does not
enable live Elastic or Splunk forms or establish their compatibility.

## 2. Create the Indexer account and review all effective permissions

These are administrator steps in the Wazuh Dashboard, with backup and rollback:

1. Sign in to your local Wazuh Dashboard as an administrator.
2. Open Indexer management → Security → Internal users → Create internal user.
   Create a dedicated technical user, for example `aegis_reader`, and set its own
   password in Wazuh. This username is illustrative; no password is supplied here.
3. Open Security → Roles → Create role, for example `aegis_index_reader`, scoped
   only to the index/pattern approved for this environment. Review the permission
   table below. Do not use an all-indices wildcard scope.
4. Use Mapped users → Manage mapping to map the internal user to that role.
5. Review every mapped role, backend role and inherited grant. A narrow new role
   does not remove broader permissions already granted elsewhere.
6. Return to AEGIS Connections, load the public CA, enter the dedicated account
   and newly created password, then test the connection.

The Dashboard read-only example is broader than this reader needs. Do not copy
its index-wide scope, tenant or Server API roles into an Indexer-only account.
See the official [Wazuh user and role mapping guide](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html).

| Operation | Permission review for the actual deployment |
| --- | --- |
| Scoped search/evidence reads | `read` on the reviewed index/pattern |
| Continuation of search contexts | `indices:data/read/scroll` |
| Cleanup of search contexts | `indices:data/read/scroll/clear` |
| Composite read group | Review the actual expansion of `cluster_composite_ops_ro` and grant only the needed actions |

Do not substitute `cluster_composite_ops` without `_ro`: it includes write/bulk
capabilities. Review effective action-group expansion rather than assuming a
group name proves least privilege. These permission requirements still need native
4.14.4 lab acceptance, including search, scroll and cleanup. The onboarding probe
uses a bounded zero-hit query and does **not** test scroll/clear-scroll.

`DELETE /_search/scroll` closes a search context; it does not delete evidence
documents. The verb alone is not a privilege classification. Do not grant document
write/delete or cluster administration, and do not attempt real evidence writes or
deletes to prove denial. Review policy and effective grants with the administrator.

**Không chứng minh tài khoản không có quyền ghi**: a successful query only shows
that the tested operation was permitted, not that write privilege is absent.

Official references: [OpenSearch action groups](https://docs.opensearch.org/latest/security/access-control/default-action-groups/)
and [scroll/search-context cleanup](https://docs.opensearch.org/latest/api-reference/search-apis/scroll/).

## 3. Obtain and inspect the public HTTP CA

Read `plugins.security.ssl.http.pemtrustedcas_filepath` in the actual Indexer HTTP
configuration. `/etc/wazuh-indexer/certs/root-ca.pem` is a default deployment
example, not a promise about custom installations. The administrator must resolve
the configured path and supply the correct public CA bundle. See the official
[HTTP API configuration](https://documentation.wazuh.com/current/user-manual/indexer-api/configuration.html).

Transfer only public certificate PEM using a trusted channel. Compare each CA's SHA-256
certificate fingerprint through a separate trusted channel with the administrator. Never copy
`root-ca.key`, server/admin private keys or any other private key. Do not confuse
a leaf certificate with a CA certificate. See the official
[certificate deployment guide](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/certificate-deployment.html).

This is a **read-only inspection command**, run manually after replacing the
placeholder with the administrator-confirmed public CA path:

```text
openssl x509 -in <configured-public-ca.pem> -noout -subject -issuer -dates -fingerprint -sha256
```

This command reports the SHA-256 fingerprint of the first certificate's DER
encoding, not a hash of the whole PEM file. For a bundle, separate copies of the
public certificates into individual PEM files, run the command for each, and
compare **every certificate fingerprint** with the administrator through the
independent trusted channel.

The UI label **Nội dung PEM/bundle SHA-256** (`ca_sha256`) instead identifies the
SHA-256 of the entire submitted ASCII PEM content: all certificates, their order,
whitespace and line endings. This immutable integrity digest is not a certificate
fingerprint. For an ASCII PEM file without a BOM it equals the whole-file hash:

```text
sha256sum <configured-public-ca.pem>
```

The existing browser upload decodes UTF-8 with `File.text()`, which removes an
initial UTF-8 BOM but preserves CRLF/LF. Therefore an original file with a BOM
does **not** have the same whole-file hash as the submitted content. This read-only
Python command computes the displayed content digest for either case without
changing the file or normalizing line endings (replace the placeholder):

```text
python -c "from pathlib import Path; import hashlib; print(hashlib.sha256(Path('<configured-public-ca.pem>').read_bytes().decode('utf-8-sig').encode('ascii')).hexdigest())"
```

Keep the approved file unchanged. Changing whitespace, line endings or certificate
order changes the content digest even if individual DER fingerprints stay the
same. Compare the content digest at confirmation and verify trust separately using
each certificate fingerprint. The API and stored digest meaning are unchanged.

Check validity dates and CA basic constraints, and inspect the deployed HTTPS leaf
certificate to ensure its DNS/IP SAN matches the URL. A CA fingerprint differs
from the leaf fingerprint. Do not export a private key to inspect certificates.
The browser only reads a public CA file up to 64 KiB into memory; the server
validates the whole PEM bundle, rejects keys/trailing data, expired certificates
and non-CA certificates. Chain and SAN verification cannot be disabled. This slice
requires explicit CA upload; it has no system-trust or insecure mode.

## 4. Test, confirm and save

1. In Manager → Kết nối → Thêm Wazuh, enter the name, environment, exact HTTPS
   Indexer origin (no path/query/fragment), reviewed index, technical username,
   public CA and password. Load the CA before entering the password: endpoint/CA
   edits clear it and require re-entry. No credentials enter URLs or browser storage.
2. Kiểm tra runs policy → TLS chain/SAN → authentication → bounded `size:0`
   query, with a total 10-second probe deadline and 64 KiB response limit.
   An Indexer 401 means authentication failed, even if the endpoint responded.
   Success requires a positive, complete shard summary with exact integer counts,
   no failed shards, no timeout or early termination and an empty hit list. Zero
   target shards, missing or inconsistent counts fail with `query_failed`; actual
   alert hits are never required.
3. Xác nhận snapshot shows name, environment, endpoint, index, **Nội dung PEM/bundle SHA-256** and
   tested_at. Save within the five-minute draft TTL. Any input edit invalidates
   the test. Closing the form, logout or a session/CSRF change clears private
   browser memory. Saving clears the password and does not bind a machine.
4. Chuẩn bị nguồn explicitly chooses the saved version as candidate using the
   expected current candidate. Its original test must still be fresh. Refresh and
   review if another administrator changed the selection. Candidate selection
   never activates a source, worker admission, machine binding or execution.

| Visible status | Meaning |
| --- | --- |
| Chưa kiểm tra / kiểm tra hết hạn | No fresh tested snapshot; test again |
| Truy vấn thành công | Tested policy/TLS/auth/query passed; not least-privilege proof |
| Đã lưu, chưa gắn máy | Immutable version saved; machines retain their existing source |
| Candidate — chưa kích hoạt | Explicit selection, not active |
| `waiting_configuration` | Worker waits for later reviewed configuration, without a healthy lease or Ready claim |
| Legacy — chỉ đọc | Existing connection retained; no credential reads through this UI |

Only `manage_connections` can read source metadata or use test/save/prepare.
Existing `view` users may read this packaged guide. No guide step executes commands
or loads remote content into the page; official links are optional reading.

Guide links retain vendor, version, deployment and step in a closed hash route,
for example `/manager/#integration/wazuh/4.14.4/self-managed/account` or the same
route ending in `/ca`. Reload, browser back and hash changes restore the selected
guide step. Unsupported products, versions, deployments or steps display an honest
unsupported message. Connection endpoints and credentials never enter these URLs.
Opening a guide closes private form state; returning does not revive a draft.
Release/review/provenance metadata is available under **Chi tiết kỹ thuật**;
normal guide copy states that lab verification is still pending.

## 5. Troubleshooting, expiry, rotation and revoke

| Fixed diagnostic | Next review |
| --- | --- |
| `policy_denied` | Administrator checks exact origin/port/index, approved IPs, DNS and root-owned policy |
| `connection_unavailable` | Check Manager-to-Indexer route and service availability |
| `invalid_ca`, `tls_failed` | Check public CA, chain, clock, expiry, fingerprint and SAN; retain verification |
| `authentication_failed` | Check dedicated internal user and credential |
| `query_denied` | Review index scope, role mappings and effective read grants |
| `query_failed` | Administrator reviews source configuration without publishing raw upstream errors |
| `draft_expired`, `draft_conflict` | Test a new snapshot |
| `source_conflict`, `candidate_conflict` | Reload current versions/candidate and review again |
| `storage_unavailable` | Check native Linux Manager and private storage configuration |
| `rate_limited` | Wait, then retry within the bounded workflow |

For credential/CA **rotation**, create a new source version with newly supplied
credential/CA, test and save. History and previous registrations are immutable.
If endpoint or CA changes, re-establish trust before supplying new credentials.
Passwords are never fetched to prefill the form. Monitor certificate expiry and
schedule rotation before it expires; test again after trust changes.

To **revoke**, have the Wazuh administrator review the account/role impact on
the currently active source and revoke its credential/mapping through the approved
Wazuh process. Selecting a candidate does not switch the active source. Rollback
Wazuh changes through the reviewed backup procedure; do not overwrite registrations,
reset jobs or change scenario ground truth. Native Linux ownership/transport gates,
effective permissions and direct TLS/lab acceptance remain pending separate review.
