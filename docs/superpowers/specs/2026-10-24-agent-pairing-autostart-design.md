# Windows/Linux pairing and boot startup

Status: implementation amendment to the approved 2026-10-23 Manager design.
Authority: owner requested implementation of IP + one-time pairing, persistent reconnect,
Windows/Linux boot autostart, delegated implementation/review and a combined command guide.
This supersedes the old foreground-only default in section 6.2 of that design.

## Intent and scope

An owner opens **Máy / Thêm máy**, generates an environment-bound pairing code,
then installs the agent and enters that code at a hidden prompt. No web-account login
is required on an endpoint. Subsequent boots reuse the endpoint's private identity.
Manager runs on Linux; supported new endpoints are Windows x64 and Ubuntu 24.04 x64.
This slice provides registration, Online/Offline, revocation and automatic reconnect.
Newly paired Windows/Linux identities are presence-only, with no scenario leasing.
Existing Windows v1 execution, CurrentUser certificate, pilot 009, scenario ground truth,
catalog, evidence and signing bytes remain compatible. No live VM migration or merge.

## Approaches and builder decisions

The owner chose the previously discussed persistent identity + one-time pairing approach.
Reusing a web password would couple unattended endpoints to human sessions; accepting an
IP without authenticated TLS would not establish Manager identity. Neither meets that choice.
The builder selects Windows SCM and Linux systemd for the explicitly requested boot startup.
Windows uses a narrow native SCM host with the existing dependency-free .NET pattern;
Linux runs the same ordinary console agent as a system service. Adding the Microsoft
WindowsServices hosting dependency was considered; the small presence process needs only
start/stop/cancel/status and will instead get actual SCM integration coverage.
No new runtime dependencies are planned. The existing cryptography library implements
the restricted enrollment issuer; the new agent uses the .NET 10 BCL.

## Manager identity and pairing

Extend `control.Device`: `connection_kind` defaults to `legacy_v1` for existing rows;
new rows use `paired_presence`. Add nullable OS/architecture/version, enrollment and
certificate validity metadata and server-received last heartbeat. Absent Wazuh mapping
is `null`, never a fabricated ID. v1 authentication, approval and claim must reject
paired_presence even if a technical operator adds a mapping or job manually.

New `devices` app owns hashed pairing codes and append-only bounded enrollment audit.
Code: 32 cryptographically random bytes encoded as 64 lowercase hex characters;
validity exactly 600 seconds, one successful redemption. Store only SHA-256 of the code,
approved environment, issuing user, timestamps, consumed device and revocation state.
Mint/revoke require fresh `view` + `manage_devices`, session/CSRF, under the existing
account authority lock. Redemption acquires that lock before the code row and rechecks
the issuer remains active with manage_devices. An expired/revoked/consumed code fails
with one indistinguishable error; a locked/demoted issuer's unused code cannot enroll.
Never put a code in URL, argv, environment, logs, audit or a download.

Anonymous machine enrollment is HTTPS only, strict bounded JSON with duplicates,
unknown keys and unsupported values rejected. The only accepted CSR key is RSA 3072–4096
bits with a valid SHA-256 signature. Issuer chooses a new UUID, generation 1, UUID SAN,
clientAuth EKU, digital-signature key usage, non-CA leaf and 30-day validity. Requested
CSR subject/extensions do not grant identity or capabilities. Issue certificate, create
device and consume code in one PostgreSQL transaction; signing errors roll back.
Use a separate new CA under Manager private root; preserve existing pilot/Server/job keys.
An explicit idempotent initialization command creates the CA only when neither file
exists, validates matching key/public certificate/CA usage/expiry on reuse and refuses
partial state. Initialization never prints a key or replaces an existing CA.

Strict one-use recovery policy: do not reuse a consumed code even for the same CSR.
The agent persists its pending private key/CSR before contacting Manager. If a response
is lost, it reports enrollment outcome unknown and keeps that pending state. Owner
revokes any orphan Offline device, issues a replacement code, and retries connect with
the same pending key. No automatic reenrollment or duplicate identities on restart.

## Wire contract (shared verbatim by tasks)

Paths have no trailing slash and never redirect. All JSON object schemas are closed.
Protocol string: `2.0`. Times are RFC3339 UTC. Machine errors are
`{"error":{"code":"<fixed_code>"}}`, without request content or exception text.
Enrollment errors: invalid_request 400; pairing_denied 403; issuer_unavailable 503.
Heartbeat errors: invalid_request 400; identity_denied 403; temporarily_unavailable 503.
Human unknown code/device resource: invalid_request 400; attempting paired-only revoke
on legacy identity: device_conflict 409. Keep these fixed errors in devices, not an
unrelated expansion of the accounts error vocabulary.

`POST /agent/v2/enroll` (no client cert required, no browser session):
request `{protocol,pairing_code,csr_pem,hostname,os,architecture,agent_version}`.
`os` is `windows` or `linux`; architecture is `x64`; agent_version is `0.1.0`.
Hostname is nonempty, <=255 visible characters, with no control characters;
csr_pem <=8192 ASCII bytes; body <=16384 bytes. Success 201:
`{protocol,device_id,environment_id,generation,certificate_pem,issuer_pem,expires_at,heartbeat_seconds,offline_after_seconds}`.
Last two values are 15 and 60. Certificate response must match the locally generated
key, UUID SAN, clientAuth, non-CA and issuer; reject malformed/foreign response before
promoting pending state. The server issuer PEM is for the client certificate chain,
not a replacement for the separately trusted server TLS CA.

`POST /agent/v2/heartbeat` (verified mTLS): request `{protocol,device_id,generation}`;
success 200 `{protocol,server_time,heartbeat_seconds,offline_after_seconds}`.
Identity is fingerprint + paired kind + generation + UUID, not body/hostname alone.
The application trusts only loopback nginx with HTTPS and verified certificate headers.
Revoke and heartbeat serialize on the device row. Use server time for last heartbeat;
Online iff valid/unrevoked and `0 <= now-last_heartbeat_at < 60 seconds`. Enrollment
alone is Offline. Expired/revoked status takes precedence; legacy presence is `unknown`.

`GET /api/v1/devices?page=1&search=...`: session + view; page size 50, stable UUID order;
response `{results,count,page,page_size}`. Each DTO:
`{id,hostname,environment_id,wazuh_agent_id,connection_kind,os,architecture,agent_version,generation,status,last_heartbeat_at,certificate_expires_at,execution_supported}`.
Metadata absent -> null; status online/offline/expired/revoked/unknown;
execution_supported false for paired_presence (legacy also must not be inferred ready).
`POST /api/v1/pairing-codes` body `{environment_id}` -> 201
`{id,code,environment_id,expires_at}`; environment matches `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
`POST /api/v1/pairing-codes/<uuid>/revoke` body `{}` ->204.
`POST /api/v1/devices/<uuid>/revoke` body `{}` ->204; paired identities only;
legacy identity returns conflict instead of changing the pilot through this UI.
All human writes use CSRF, current authority and no-store. No device DELETE API.

## TLS and deployment

Manager URL is a normalized HTTPS origin: IP or DNS plus optional port, no userinfo,
path, query, fragment or redirect. IP URLs require exact iPAddress SAN, not a DNS SAN
containing IP text. Owner distributes the public Server CA through a trusted channel.
Never TOFU/download-and-trust, disable name/chain/time checks or switch to HTTP.
New client TLS validation uses only explicitly supplied server trust and hostname;
client identity chain uses the enrollment issuer. Requests bypass proxies and redirects.
Keep legacy /agent/v1/ mTLS unchanged. nginx gets an exact bootstrap location stripping
all identity headers, a rate/body limit, and exact mTLS heartbeat location. nginx trust
bundle includes legacy and new enrollment public CA, preserving pilot trust.
Guide gives configurable inputs for allowed host, server TLS IP SAN/public CA, issuer
init, trust bundle/reload and migration; no hardcoded lab IP or credentials.

## Endpoint process and persistence

New project `agent/connection/Aegis.Connection` is separate from the legacy Windows
runner. Executable `aegis-agent[.exe]`: `connect --manager <https-origin> --server-ca
<absolute-public-pem> --state-dir <absolute-path>` prompts with echo disabled;
`run --state-dir ...`, `status --state-dir ...`, and Windows-only `service --state-dir ...`.
There is no code option/env fallback. `connect` refuses an existing enrolled identity;
unattended startup never calls connect. State contains local RSA key, certificate/issuer,
origin, trusted public Server CA and identity metadata. Use staged atomic state writes,
exclusive process/state lock, bounded reads and strict parsing, reject symlink/reparse
state components, malformed state and insecure permissions rather than overwrite.
Key stays local in a PKCS8 PEM protected by service-account filesystem permissions;
no private export in packages/status/logs. This follows the builder's portable choice;
nonexportable CNG/TPM binding is not promised. No legacy CurrentUser key import.

Heartbeat every 15s after initial immediate attempt, request timeout 10s, response cap
16384 bytes; transient network/429/5xx retries use exponential backoff from 2s capped
60s plus bounded jitter, cancellation interrupts requests and wait. Authorization denied
or certificate expired reports action needed and stops successfully reconnecting; never
claims Online locally without a successful response. Status distinguishes enrolled,
last acknowledged contact and terminal failure; Manager is the authority for Online.
No scenario, polling, PowerShell runner, evidence evaluation or Wazuh settings in this core.

Windows SCM service name `AegisAgent`, dedicated virtual account `NT SERVICE\AegisAgent`,
Automatic (Delayed Start) and failure restart, starts before interactive login. Binary
root `%ProgramFiles%\AEGIS Agent`, state `%ProgramData%\AEGIS\Agent`; owners ACL restricted
to SYSTEM/Administrators and service SID (read/execute binary, modify state). Quote
absolute SCM paths. Explicit STOP/SHUTDOWN cancels, reports status and exits within 20s.
Linux root-owned binary `/opt/aegis-agent`, dedicated system user/group `aegis-agent`,
state `/var/lib/aegis-agent`0700/files0600, systemd Type=simple, Restart=on-failure,
network-online ordering with retry for delayed network, multi-user.target enable.
Service cannot modify installed binaries; no root/LocalSystem execution.

Installers require admin/root, validate artifact hash manifest and package layout before
changes, stage binaries, refuse foreign service/path/account/insecure existing state,
preserve identity on reinstall/update/start failure. Existing compatible service may be
stopped to update and restarted. Fresh Windows service is created disabled before applying
service SID ACL; connect runs elevated with the same protected machine state, then enables
and starts only after success. Linux connect runs as the dedicated service user. Failed
pairing leaves enrollment pending and service disabled; rerun resumes without new key.
Uninstall stops/removes service and binary, keeps protected identity/config by default;
no implicit purge. Normal reinstall reuses enrolled state without asking for a code.
Installer/scripts never embed a code/password/private key. Document service conflict,
pending outcome recovery, reboot verification, offline restart and expiry/revoke recovery.

Explicit recovery: stop the service, then run `retire --state-dir <path> --device-id
<current-UUID>` with the service's state authority. It requires an exact identity match
and exclusive state lock, moves the complete identity into a newly protected retired
subdirectory without deleting it, then permits a new connect at the configured path.
The owner revokes the old identity on Manager before replacement (expiry alone does
not remove it). Refuse mismatched UUID, active state lock or insecure archive; failure
must leave a recoverable identity. Reinstall/start uses the new enrolled identity only
after successful connect. This is an explicit builder recovery decision, not ordinary
restart behavior; tests cover preservation and commands are in the combined guide.

## UI and verification

Reuse approved Manager visual style/auth generation guards. Enable **Máy** for view,
list status/OS/host/environment/last contact/expiry, refresh without overlap, abort on
session/logout/authority change. Thêm máy and revoke require manage_devices. Dialog
shows code once and deadline, warns about HTTPS trust, explains no endpoint account
login, closes/clears on logout/expiry and never stores code in URL/localStorage/clipboard
without owner action. Render data as text. Show Online does not imply scenario-ready.

Each implementation part has RED/GREEN tests and an independent spec/quality review.
Required real gates: PostgreSQL redemption and revoke races; shipped nginx bootstrap/
heartbeat/spoof/legacy trust; .NET client to actual Django issuer over real TLS; Windows
SCM install/start/stop/account/ACL/preserve; Linux native/systemd validation; frontend
authority/late-response/secret clearing; existing core and legacy signing regressions.
CI supplies isolated Linux/Windows environments; host desktop/lab is not modified.
Real reboot-before-login and approved deployment certificates/targets are reported as
owner lab gates unless performed on an explicitly authorized disposable VM.

Deliver self-contained win-x64/linux-x64 archives, SHA-256 manifests, install/uninstall
scripts and one Vietnamese quick-start/runbook with prerequisites and all commands.
No target SDK required; document native Ubuntu dependencies. Never bundle real secrets,
keys/certs/evidence. Package source commit and successful CI references for review;
draft PR stacks on Part1 and requires human review/lab validation before merge.
