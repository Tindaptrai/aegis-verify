# Pinned runtime notices

These are byte-for-byte copies of the root `LICENSE.TXT` and
`THIRD-PARTY-NOTICES.TXT` from the official Microsoft NuGet runtime packages
`Microsoft.NETCore.App.Runtime.win-x64` and `Microsoft.NETCore.App.Runtime.linux-x64`
version `10.0.13`, reviewed on 2026-10-25. Each RID has different bytes; do not
substitute one RID's files for the other or normalize their line endings.

Package URLs and SHA-256 digests are pinned in
`scripts/agent_connection_runtime_files.json`. The builder requires exactly these
two regular, nonlinked files in each selected RID directory and verifies their
digests before producing any output. No NuGet cache discovery/copy runs at build
time. A runtime upgrade must review/update the inventory and both notice sets.

Both files and `DOTNET-RUNTIME-NOTICES.json` (package/version/RID/source/digests)
ship under `bin/`, covered by `SHA256SUMS.txt`, so the Windows bin-only copy and
Linux package copy retain them alongside the installed runtime. The focused
`.gitattributes` rule preserves the exact upstream bytes across checkouts.
