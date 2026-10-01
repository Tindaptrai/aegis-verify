# Issue #112 — Indexer CA chain, review and rotation plan

Status: **done** (2026-10-01) with the lower-impact option in section 2, re-issuing
the same CA. The plan below is kept as written on 2026-09-27; the outcome is in the
last section. Keep all private values and certificate files outside Git.

## Observed failure and scope

The owner's read-only check over a temporary approved tunnel reached the Wazuh
Indexer on Windows Python 3.12 and received the expected unauthenticated HTTP 401.
Python 3.13 failed TLS verification first with OpenSSL verify code 92, `CA cert
does not include key usage extension`. The separate Wazuh Server API returned
HTTP 401 on both Python versions. The tunnel was closed. These observations are
recorded in [issue #112](https://github.com/Tindaptrai/aegis-verify/issues/112).

Python 3.13 enables `VERIFY_X509_STRICT` in `ssl.create_default_context()`.
OpenSSL's strict verifier requires a CA certificate to include the Key Usage
extension. This is a certificate-chain problem; do not disable strict verification,
hostname checks or TLS in AEGIS to make collection work. The exact offending CA
certificate and its fingerprint **have not yet been identified**. A replacement
cannot be chosen safely until the chain and every consumer are inventoried.

References: [Python 3.13 SSL change](https://docs.python.org/3.13/whatsnew/3.13.html#ssl),
[OpenSSL strict verification](https://docs.openssl.org/3.2/man1/openssl-verification-options/),
[Wazuh certificate deployment](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/certificate-deployment.html).

## 1. Read-only inventory, before a change request

The operator and lab administrator work in the private lab record, not in this
repository. Use the previously approved temporary tunnel and the configured CA
bundle. No credentials are needed for the initial TLS/HTTP 401 probe.

1. Record the deployed Indexer node certificate chain, the configured local CA
   bundle, and the certificate paths referenced by Indexer, Wazuh dashboard,
   Filebeat and any other Indexer clients. Record each certificate's SHA-256
   fingerprint, subject, issuer, serial, validity, Basic Constraints, Key Usage,
   Extended Key Usage and SAN. Never copy a private key into the record or repo.
2. Inspect **each CA certificate** in the presented and trusted chain. Name the
   certificate missing Key Usage by its fingerprint and chain position. Verify
   whether the configured CA bundle and the live Indexer chain refer to the same
   trust anchor. Do not assume the root is the offender merely because the error
   contains `CA cert`.
3. Reproduce the strict-chain failure with the approved hostname and CA bundle.
   Check that the failure occurs before HTTP, while the Server API remains a
   separate passing control. Preserve sanitized command output and fingerprints
   in the private lab record. A 401 proves TLS reached HTTP; it does not prove
   the collector account's permissions.
4. Inventory all trust consumers and node/client certificates signed by the
   affected CA. Wazuh uses its CA across Indexer, dashboard and Filebeat, so a
   root CA replacement may require coordinated certificate and trust updates.
   Confirm the actual topology and Wazuh version before selecting commands.

Stop if a fingerprint, hostname, certificate role or consumer is uncertain.

## 2. Change package for administrator review

Prepare the following outside Git. The administrator reviews and approves the
complete package and maintenance window before deployment:

- The exact offending CA fingerprint, why strict verification rejects it, and
  the list of dependent certificates, services and trust files.
- A newly issued, version-appropriate CA/chain with `CA:TRUE` Basic Constraints
  and Key Usage permitting certificate signing (`keyCertSign`); appropriate
  node/client certificates with reviewed SAN and usage. Validate the replacement
  chain offline with strict verification and the intended DNS identity. A signed
  certificate's extension cannot be repaired by editing its PEM text.
- Secure backup of the currently deployed public certificates, private keys,
  trust files and relevant service configuration, plus their fingerprints and
  permissions. Specify the exact restore order, responsible administrator and
  expected service interruption. Keep backups and keys in approved private
  storage, never in an evidence bundle or the Git checkout.
- A consumer-by-consumer deployment sequence that avoids a half-rotated trust
  state. Use the procedure for the lab's installed Wazuh version and topology;
  verify Indexer cluster health and event forwarding after each service restart.

### Lower-impact option to evaluate first: re-issue the same CA

If the offending certificate is a CA whose private key the administrator still
holds, it may not need a new key at all. Issue a replacement certificate for the
**same key pair and subject**, keeping the Subject Key Identifier, with a new serial,
`basicConstraints=critical,CA:TRUE` and `keyUsage=critical,keyCertSign,cRLSign`.
Certificates already signed by that CA keep verifying, because their issuer name
and signature still match the same subject and key. Only trust stores then need the
re-issued certificate, starting with the AEGIS CA bundle, and the node certificates,
Indexer, dashboard and Filebeat can stay as they are.

This is a hypothesis for the review, not a tested procedure:

- Test it offline first: `openssl verify -x509_strict -CAfile <re-issued CA>
  <current node certificate>` must pass, and the Python 3.13 probe in section 3
  must pass with the re-issued CA as `cafile` while the Indexer still presents its
  current chain. Recent OpenSSL builds the chain from trusted certificates first,
  but whether a CA copy sent by the server still affects the result has to be checked.
- If the offender is an intermediate rather than the root, re-issue that
  intermediate the same way, signed by its own issuer.
- The CA private key stays in the administrator's approved storage. Never copy it
  into this repository or an evidence bundle.
- If any check fails, fall back to the full rotation above.

The local AEGIS CA bundle is updated only after the administrator confirms the
new public CA fingerprint through a trusted channel. Keep the old bundle for
rollback until acceptance completes. Do not change AEGIS parsing, scenario
ground truth, detection rules or raw evidence for this issue.

## 3. Post-rotation validation

1. Reopen a temporary approved tunnel. With Windows Python 3.13,
   `ssl.create_default_context(cafile=...)` must verify the Indexer certificate
   and hostname and reach the expected unauthenticated HTTP 401. Repeat the
   Server API control on Python 3.12 and 3.13. Keep strict verification on.
2. Confirm Indexer, dashboard and Filebeat are healthy and that a known recent
   event still reaches the Indexer. Compare new peer/CA fingerprints with the
   administrator-approved change package.
3. With the approved least-privilege Indexer principal, run one read-only,
   bounded collection of a known window into a new owner-only output directory.
   Review `query_complete`, `record_count`, cleanup status, the exact query
   window, evidence IDs, raw references and SHA-256 hashes. Validate a nonempty
   bundle only with a separately reviewed profile/context. An empty query is
   diagnostic and must not become a missing-detection verdict.
4. Save a sanitized acceptance record with Python/OpenSSL versions, certificate
   fingerprints, service health, collection scope, result counts and the private
   evidence record location. The lab administrator and project owner review it
   before closing #112. Restore the old chain and trust configuration if TLS,
   service health or forwarding fails; record the failed step and recheck the
   original Python 3.12 path after rollback.

Until this is complete, use the tested Python 3.12 environment for an optional
live Indexer demonstration. The [offline customer walkthrough](DEMO_WALKTHROUGH.md)
uses sanitized bundles and does not depend on Indexer connectivity.

## Outcome (2026-10-01)

- **Offending certificate.** A read-only inventory found it: the Wazuh root CA. It
  has `CA:TRUE` but no Key Usage, and the Indexer and dashboard present only leaf
  certificates signed directly by it. The Server API uses a separate self-signed,
  non-CA certificate and was not affected. `openssl verify -x509_strict`
  reproduced error 92 at depth 1.
- **Offline test.** The same-key option was proven first with a throwaway CA of the
  same shape, including the `OU, O, L` name order:
  - `openssl verify -x509_strict` passed with the re-issued CA;
  - a real Python 3.13 TLS handshake passed, even when the server also sent the old CA;
  - Python 3.12 accepted both CAs.

  The Subject Key Identifier computed from the real root's public key equals the
  existing one. The commands were then rehearsed on the manager's own OpenSSL 3.0.
- **The change.** The project owner, as lab administrator, re-issued the root
  certificate on the manager with sudo. They used the same key and subject, a new
  serial, `basicConstraints=critical,CA:TRUE` and
  `keyUsage=critical,keyCertSign,cRLSign`. The temporary key copy was shredded. No
  node certificate, Wazuh service or Wazuh trust file was changed; Indexer,
  dashboard and Filebeat still trust the original root. Only the AEGIS operator's
  local `cafile` now points at the re-issued certificate, and its fingerprint was
  confirmed through the owner's terminal. Rollback is pointing `cafile` back to the
  original root.
- **Acceptance.** Through a temporary tunnel, with no credentials, Windows Python
  3.13 rejected the old CA with verify code 92 and reached HTTP 401 with the
  re-issued CA. The Server API reached HTTP 401 on Python 3.12 and 3.13. A
  read-only `--adaptive` collection with the least-privilege principal then ran on
  Python 3.13 over a known 21-minute window:
  - `query_complete` true, `cleanup_failed` false, `collection_assurance` unknown;
  - 268 records in four contiguous leaves (38/83/55/92);
  - every manifest and input hash matched;
  - 268 canonical events with 268 distinct evidence IDs.

  Three earlier attempts kept their `INCOMPLETE` markers and are not evaluated: a
  mistyped principal, a non-adaptive run over the 100-record limit, and one
  unlogged failure.

Python 3.13 is no longer limited to the offline demo for live Indexer collection.

