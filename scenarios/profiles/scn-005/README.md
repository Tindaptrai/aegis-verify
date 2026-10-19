# SCN-005: safe PowerShell through Elastic

This separate Lab B draft evaluates an approved benign PowerShell execution.
It leaves the Wazuh ground truth in SCN-001 unchanged. It is a reviewable
implementation, not a claim of upstream acceptance or a regression result.

The profile consumes three distinct canonical witnesses from `elastic`:

| Assertion | Required witness |
| --- | --- |
| A01 | Sysmon process creation: the bound hostname, child PID and full executable, Windows Sysmon provider, observed action and a command line. |
| A02 | Complete single-part PowerShell 4104 telemetry for the bound hostname/PID and Windows PowerShell provider. The explicit parser rejects incomplete or multipart blocks. |
| A03 | An alert produced by `elastic-security`, with reviewed rule ID `aegis-labb-safe-powershell-v1`, joined to A02 on hostname/PID. |

`target_host`, `child_pid` and `powershell_image` come from the run's measured
receipt and native evidence, through `context.json`. Use the complete executable
path, not its basename. `context.example.json` contains synthetic identities only;
the interval must cover the actual source and alert observation budget.

Source Windows event time is the unchanged XML `System.TimeCreated`. Alert time
is the first detection time, `kibana.alert.start`. The reviewed interval is
**0 through 120 seconds**, inclusive, after the script witness. This is a separate
planned Lab B alert observation interval; it does not widen SCN-001 or reinterpret
alert time as original script time.

The engine verifies the hostname/PID/time witness. Exact Elastic ancestor
index/document linkage, the marker text, script-block identity, payload hash,
parent process and original EVTX record are independently audited from the
unchanged raw bytes and parser provenance. This profile does not claim the
engine evaluates those source-specific fields. An alert cannot substitute for
source telemetry because its canonical producing provider is different.

Do not claim `False negative` from a missing alert without an independently
justified complete-collection declaration pinned to the event set/profile/scope.
The example deliberately has no such declaration. A baseline that does not run
the marker is a control case, not a failed approved marker execution. Historical
exports evaluated under this contract must be labelled retrospective replay.

See [Lab B integration](../../../docs/LABB_ELASTIC.md) for parser keys and commands.
