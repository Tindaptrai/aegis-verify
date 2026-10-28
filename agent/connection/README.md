# Presence connection client

`Aegis.Connection` is the .NET 10, dependency-free Windows x64 / Linux x64
connection client, version `0.3.0`, for presence `2.0` and network heartbeat `2.1`.
The executable is `aegis-agent`. Default installation registers an identity and
sends heartbeats. Reviewed Windows execution v2 requires explicit local opt-in;
Linux remains presence-only.
This identity is independent of the legacy Windows v1 runner and its
CurrentUser/My certificate provisioning.

Vietnamese package installation, service commands, recovery and owner lab gates:
[Agent connection runbook](../../docs/manager/AGENT_CONNECTION_RUNBOOK.md).

Build and run the synthetic harness from the repository root:

```powershell
dotnet build agent/connection/Aegis.Connection -c Release
dotnet run --project agent/connection/Aegis.Connection.Tests
```

Self-contained publishing pins runtime `10.0.13`; framework-dependent development
uses the installed .NET 10 runtime. Packaging and native service installation are
handled by the deployment tasks. This project does not install a host service.

Supply the HTTPS origin and a public Server CA received through a trusted channel.
All paths must be absolute. An origin has only an IP/DNS authority and optional
port: no userinfo, trailing slash, path, query, or fragment. The supplied CA must
be a single public certificate PEM. The client never downloads or trusts a CA
received from an unverified server.

```powershell
& $AgentExecutable connect --manager $ManagerOrigin --server-ca $ServerCaPath --state-dir $StateDirectory
& $AgentExecutable run --state-dir $StateDirectory
& $AgentExecutable status --state-dir $StateDirectory
```

`connect` prompts with echo disabled in an interactive console. It also accepts
one bounded line on redirected stdin for a parent installer or CI child process:
exactly 64 lowercase hex characters followed by LF, CRLF or EOF. Oversized,
malformed or extra-line input is rejected without a request or echo. The parent
must write the code directly into the child stdin pipe and close it; do not place
the code in command text, shell history, files, URLs or environment variables.
Obtain a fresh environment-bound one-time code from the owner. There is no
command-line or environment code option. `connect` makes one enrollment attempt, saving its
pending key/CSR before sending. It refuses an already enrolled state. A retry with
a replacement owner code reuses the pending key and the same origin/Server CA.

An uncertain enrollment response leaves `enrollment_outcome_unknown`. The owner
must reconcile/revoke any orphan device and issue a replacement code. Restarting
`run` never enrolls or asks for a code. `pairing_denied` likewise retains the
pending identity for an owner-directed retry.

`run` immediately attempts a heartbeat, then waits 15 seconds after each accepted
response. Requests are bounded to 10 seconds and responses to 16,384 bytes.
Transient network errors, HTTP 429 and 5xx use exponential waits of 2–60 seconds,
with up to 20% added jitter and a final 60 second cap. Acknowledgement resets
backoff. Bounded proxy error bodies are discarded as transient responses; they
never grant an identity or acknowledge a heartbeat. Accepted success and fixed
4xx decisions require closed, duplicate-free JSON schemas. Redirects and proxies
are disabled. Ctrl+C and Linux SIGTERM cancel requests and waits.

Server TLS uses the explicitly supplied Server CA and verifies chain, lifetime,
serverAuth and hostname. An IP origin requires an exact iPAddress SAN. Enrollment
issuer PEM authenticates only the client identity chain, and never replaces the
Server CA. Promotion verifies the returned RSA key, sole UUID URI SAN
`urn:aegis:agent:<lowercase-UUID>`, issuer, clientAuth, non-CA leaf, digital-signature
usage, expiry and fixed protocol fields. Reload checks the identity bindings again;
expired identities remain readable for status and explicit retirement.

State is one bounded, strictly parsed `state.json` containing the local RSA 3072
PKCS8 key, CSR, independent Server CA, client chain and metadata. Writes stage and
flush a protected file before atomic replacement. A process lock excludes
enrollment, heartbeat writers and retirement. Read-only status can read an atomic
snapshot while a service owns the lock. Symbolic links/reparse components and
insecure existing permissions are rejected. Linux directories must be `0700`,
files `0600`. Windows permits only the current owner, SYSTEM, Administrators and
the installed `AegisAgent` service SID. Deployment must establish the intended
service ownership/ACL before connecting. Do not place private state in the source
checkout, build output or packages.

On Windows, Schannel cannot use the ephemeral RSA key produced by `CreateFromPem`.
The client imports an in-memory PFX into an OS temporary **user** key container
under the running account, with `UserKeySet` and no `PersistKeySet`. It never adds
a certificate to a certificate store or writes a PFX file. The PFX buffer is
zeroed and the owning certificate is disposed when the connection closes.
Normal disposal deletes the temporary native key; abnormal process termination
does not guarantee cleanup. The durable identity remains the protected PKCS8
snapshot. Native service validation must verify temporary key access under
`NT SERVICE\AegisAgent`; the client does not require or substitute LocalSystem.
See [Microsoft key flags](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509keystorageflags)
and [private key lifetime](https://support.microsoft.com/en-us/servicing/dotnetframework/windows/private-key-lifetime-on-windows-and-the-january-2021-net-framework-security-and-quality-rollup).

`status` emits JSON with `device_id`, `environment_id`, `generation`,
`certificate_expires_at`, `manager_origin`, `last_acknowledged_at`, and `state`.
Absent metadata is `null`. State is `unconfigured`, `pending`, `enrolled`, or a
fixed failure code (`enrollment_outcome_unknown`, `pairing_denied`,
`identity_denied`, `identity_expired`, `response_invalid`). Local acknowledgement
time records when a valid heartbeat response arrived. Manager is the authority
for Online/Offline; a running process does not establish Online status. Status
does not include PEM, private key, CSR, pairing code or a token.

For an expired/revoked identity, the owner first revokes the old Manager device,
then stops the service and explicitly retires the matching local UUID:

```powershell
& $AgentExecutable retire --state-dir $StateDirectory --device-id $CurrentDeviceUuid
& $AgentExecutable connect --manager $ManagerOrigin --server-ca $ServerCaPath --state-dir $StateDirectory
```

Retirement requires the mutation lock and exact UUID. It copies the complete
snapshot into protected `retired/<UUID>-<random>/state.json`, flushes the file and
synchronizes the archive directory hierarchy before unlinking the active snapshot,
then synchronizes the source directory. Failure may leave both a protected archive
and recoverable active bytes; it never automatically erases a protected archive.
It does not contact Manager. A later successful connect creates a new
key and identity; retain the protected archive for owner reconciliation.

Exit codes: `0` success or requested run cancellation; `2` invalid command syntax;
`3` terminal identity, enrollment, filesystem or configuration action required.
Operational errors expose only fixed JSON error codes. Native boot/service,
reboot-before-login, actual Django/nginx interoperability and Linux execution
remain deployment/CI/lab gates; local harness TLS uses only synthetic temporary
certificates and inert presence requests.

## Paired Windows execution 0.3

Presence remains the installation default; Linux is presence-only. Windows opt-in
requires explicit protected profile/grant/separate exact RSA3072 execution public
pin and fresh service-local readiness. Old 0.1/0.2 state creation versions,
identity keys/certificates and durable journal entries are preserved. Follow
[the reviewed setup/recovery guide](../../docs/manager/windows-web-execution.md).
Execution receipts and health do not establish detection or collection completeness.
