# Foreground Windows agent (first flow)

Separate .NET 10 executable; no core MSI or NuGet dependencies. Copy the unchanged reviewed `demos/scn-001/Invoke-SafeDemo.ps1` and owner-approved private kit to the selected Windows VM. Never run this execution path on a development host. Configure private local paths and exact byte SHA-256 pins using `private.example.json`; placeholders intentionally cannot authorize execution. `kit_sha256` hashes kit.json bytes. Job `payload_sha256` pins the safe script; receipt `payload_sha256` hashes the signed job JSON bytes.

Provision the client certificate with its private key in Windows CurrentUser/My. Configure its lowercase SHA-256 DER fingerprint. Install the Manager CA in Windows trust on the approved VM only; the agent uses OS hostname/chain/revocation checks, disables redirect and proxy handling, and performs no TLS bypass. Signing public key is separate from the TLS CA and must be RSA at least 3072 bits.

Private config, catalog, public-key file, kit, run parent, spool and all ancestors must have ACLs limiting modification to the owner/agent account. No concurrent writers are supported. Keep spool and run parent outside the source checkout, preserve journals across restart, and create the run parent before use. Paths must be local absolute paths with no reparse points; the runner supplies further Windows path/telemetry/payload preflight. Do not restore old journals into an active identity: reconcile and enroll a new generation first.

```
dotnet run --project agent/windows/Aegis.Agent -- --config C:\AEGISPrivate\private.json --once
dotnet run --project agent/windows/Aegis.Agent -- --config C:\AEGISPrivate\private.json --validate-envelope C:\AEGISPrivate\envelope.json
dotnet run --project agent/windows/Aegis.Agent.Tests
```

`--once` replays one pending terminal receipt (or converts ambiguous recorded start/launch into execution_unknown) before polling. It polls at most once and never reruns a recorded job. A missing/failed start response prevents process creation. Receipts remain byte-identical across retries and are persisted before sending. Only the journal state changes after acknowledgement. Owner reconciliation is required for unknown execution.

Exit codes: 0 means no work, validated envelope, or acknowledged execution receipt; 2 means a fixed-vocabulary validation/protocol rejection; 3 means operational failure requiring review. Exit 0 is not a detection verdict. Detailed output stays private in the spool, capped at 1 MiB; unchanged runner study artifacts stay under the run parent. Ctrl+C cancels the owned tree; the local deadline includes the existing 120-second study window and lead time. Only children contained in the agent's kill-on-close Job Object are terminated.

The dependency-free test harness launches only itself as inert child/grandchild executables. It does not invoke PowerShell or the safe-demo runner. Live mTLS deployment, private kit review, lab telemetry and owner acceptance remain required.

The first-flow agent is version `0.1.0-preview.1`, separate from core AEGIS 0.4.0.
Self-contained Windows builds pin .NET runtime 10.0.13, the 2026-10-13 security
release in [Microsoft's release metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json).
The installed development SDK/runtime is not upgraded by this build.

```sh
dotnet publish agent/windows/Aegis.Agent -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o REPLACE_NEW_EXTERNAL_BUILD_DIRECTORY
```
