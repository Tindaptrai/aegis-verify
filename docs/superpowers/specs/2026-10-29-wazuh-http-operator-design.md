# Optional Wazuh HTTP preparation kit

Issue #163. Owner approved continuing on 2026-10-29 after clarifying that this
is an optional vendor-side operator kit, never a prerequisite built into AEGIS.
The private owner-reviewed proposal supplies the actual host, addresses and CA
pins; those values must not enter Git, application code or CI artifacts.

## Purpose and approach

The current lab has Wazuh 4.14.4 / OpenSearch 2.19.4 with HTTP and transport
bound to loopback. Its HTTP certificate has only the loopback IP SAN. Prepare
direct HTTPS without changing cluster transport or exporting the CA private key.
The owner selected direct HTTPS over a persistent SSH tunnel; an additional TLS
gateway was considered but adds an unnecessary component where a matching local
CA signing key is available. Systems with usable HTTPS skip this kit entirely.

## Contract

- Python 3.12 standard library plus existing OpenSSL, nftables and systemd; no
  product dependencies. Root-only explicit operator commands, no web invocation.
- A strict JSON deployment profile supplies the hostname, exact non-loopback
  IPv4 addresses, certificate/CA archive paths and expected public SHA-256 pins.
  Ship only a non-usable placeholder example publicly. Reject unknown fields,
  invalid addresses, links, duplicate JSON keys and untrusted ownership/modes.
- `check` performs read-only live preflight; it does not read a CA private key,
  stop a service or create a persistent intent. `apply` takes the profile hash
  and a frozen preflight hash, revalidates drift and takes a durable root-only
  backup/intent before changes. `status` is observational; `rollback` is explicit.
- Read only the two exact, regular, unique, size-bounded CA members in the
  archive; do not extract the archive or read unrelated password members. Match
  archived CA to live CA and its private key locally. Never log/export keys.
- Create a new RSA-3072 PKCS#8 HTTP key and serverAuth / CA:FALSE certificate,
  preserving the old leaf subject with exactly loopback plus the approved
  Indexer IPv4 SAN. Validity is at most 365 days and never past CA expiry. Verify
  chain, SAN, EKU, validity, subject and key pair before installation.
- Preserve `network.host`, transport/cluster/node/security fields, trust CA,
  old certificates/keys and all client configurations byte-for-byte. Patch
  only the HTTP bind/port/publish and HTTP certificate/key fields. Refuse
  unsupported YAML rather than guessing or rewriting the document. Retain
  localhost HTTPS and bind only the approved Indexer address, never wildcard.
- A separate `inet` table accepts loopback and the approved Manager IPv4 source
  to the exact Indexer IPv4 TCP 9200, and drops other sources to that tuple.
  Policy accept for unrelated traffic. Never flush the ruleset or enable UFW.
  Existing tables must remain unchanged. Reject conflicting table ownership.
- Install a root-owned oneshot guard ordered before Indexer and persistent at
  boot. Verify the exact table before every Indexer start, including restarts
  while the guard is already active. Failure must prevent a new listener.
  Stopping the guard never deletes rules. Detect conflicting firewall loaders;
  refuse configurations whose reload ordering cannot be preserved safely.
- Root-owned immutable code/profile and root:Indexer-group TLS directories
  (0750), key/certificate service-readable but not writable. Root-only work,
  backup and intent directories (0700/0600); no writable or linked ancestors.
  The CA archive may be under an owner home: securely stage its open regular
  inode into root-only storage and revalidate identity/hash before use.
- Lock concurrent operators. Atomically persist and fsync intent transitions
  before side effects; handle interruption/partial changes by refusing blind
  retries and providing explicit rollback. A failure must not strand a
  non-loopback listener without the guard. Restore original config/drop-in,
  restart old Indexer and verify localhost before deleting only the owned table.
  If recovery is uncertain, retain the guard and all evidence.
- Restart only Indexer. Local verification checks verified localhost TLS,
  exact listeners, transport still loopback and unchanged CA/transport hashes.
  Successful local apply means `pending_external_validation`, not lab accepted.
  Manager TLS, denied remote source, Dashboard, original source and reboot
  persistence require separate owner-observed acceptance. Never auto reboot.
- No account creation, security-role mutation, Manager migration, source/binding
  activation, scenario execution or PR merge. No secrets or live observations
  enter public artifacts. Fixed-vocabulary public failures; private root logs
  may hold operational errors but never key/password bodies.

## Tests and acceptance

Unit tests cover profile/config/archive rejection, certificate mismatch,
idempotency/drift, every transaction phase and rollback failure. Native Linux
tests exercise real OpenSSL and nftables in an isolated network namespace;
real systemd tests use synthetic disposable units. Never label mocks, Windows
runs or synthetic services as live Wazuh proof. Required native tests cannot
silently skip. Full vendor/lab acceptance remains an operator step.

The builder decides internal module boundaries, deterministic manifest format,
bounded command timeouts and exact safe pre-start mechanism, and records those
choices in the plan. No native proof means no live apply command is released.

## References

- [OpenSearch 2.19 network settings](https://docs.opensearch.org/2.19/install-and-configure/configuring-opensearch/network-settings/)
- [Wazuh certificate deployment](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/certificate-deployment.html)
- [systemd units](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
