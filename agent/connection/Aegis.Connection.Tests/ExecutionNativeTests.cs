using Aegis.Connection;
using Aegis.Connection.Execution;
using System.Diagnostics;
using System.Runtime.InteropServices;

internal static partial class Program
{
    private static void ExecutionNativeTests()
    {
        Test("execution policy runner allowed payload origin denied invalidates cached proof and refresh", async () =>
        {
            var (grant, facts) = PreflightFixture();
            var zones = new Dictionary<string, bool> { [grant.Profile.RunnerPath] = true,
                [Path.Combine(grant.Profile.KitDirectory, "lab_update.ps1")] = true,
                [Path.Combine(grant.Profile.KitDirectory, "maintenance_check.ps1")] = true };
            string? policy = "RemoteSigned";
            var proof = new ExecutionPolicyProof(facts, _ => true, (_, _) => Task.FromResult(true),
                path => ExecutionPowerShellPolicy.Allows(path, () => policy, path => zones[path]));
            // WLDP/SAFER and the authorized readonly runner are not payload authority.
            Check(await proof.RefreshAsync(grant, CancellationToken.None) && proof.Allows(grant), "local explicit policy did not establish proof");
            zones[Path.Combine(grant.Profile.KitDirectory, "lab_update.ps1")] = false;
            Check(!proof.Allows(grant), "cached runner proof ignored payload-only origin denial");
            Check(!await proof.RefreshAsync(grant, CancellationToken.None), "refresh accepted denied payload origin");
            zones[Path.Combine(grant.Profile.KitDirectory, "lab_update.ps1")] = true;
            Check(!proof.Allows(grant), "failed refresh resurrected old proof");
            Check(await proof.RefreshAsync(grant, CancellationToken.None), "fresh local proof failed");
            policy = "AllSigned";
            Check(!proof.Allows(grant) && !await proof.RefreshAsync(grant, CancellationToken.None), "signature-dependent policy reused local proof");
            policy = null;
            Check(!await proof.RefreshAsync(grant, CancellationToken.None), "undefined policy guessed a permissive default");
            policy = "RemoteSigned";
            var changedDuringProbe = new ExecutionPolicyProof(facts, _ => true, (_, _) =>
            { zones[Path.Combine(grant.Profile.KitDirectory, "maintenance_check.ps1")] = false; return Task.FromResult(true); },
                path => ExecutionPowerShellPolicy.Allows(path, () => policy, path => zones[path]));
            Check(!await changedDuringProbe.RefreshAsync(grant, CancellationToken.None) && !changedDuringProbe.Allows(grant), "refresh published proof despite second payload origin change");
        });
        Test("execution policy only explicit local authorization admits and scope precedence is conservative", () =>
        {
            foreach (var policy in new string?[] { null, "Undefined", "Default", "Bypass", "Restricted", "AllSigned", "unknown", "" })
                Check(!ExecutionPowerShellPolicy.Allows("fixture", () => policy, _ => true), "unsupported policy admitted");
            foreach (var policy in new[] { "RemoteSigned", "Unrestricted" })
            {
                Check(ExecutionPowerShellPolicy.Allows("fixture", () => policy, _ => true), "explicit local policy rejected");
                Check(!ExecutionPowerShellPolicy.Allows("fixture", () => policy, _ => false), "remote or unknown origin admitted");
            }
            Check(ExecutionPowerShellPolicy.Select("AllSigned", "RemoteSigned", "Unrestricted", "RemoteSigned") == "AllSigned", "machine policy overridden");
            Check(ExecutionPowerShellPolicy.Select(null, "Restricted", "Unrestricted", "RemoteSigned") == "Restricted", "user policy overridden");
            Check(ExecutionPowerShellPolicy.Select(null, null, "AllSigned", "RemoteSigned") == "AllSigned", "current user policy overridden");
            Check(ExecutionPowerShellPolicy.Select(null, null, null, "RemoteSigned") == "RemoteSigned", "explicit machine preference lost");
            Check(ExecutionPowerShellPolicy.Select(null, null, null, null) == null, "default policy invented");
            Check(ExecutionPowerShellPolicy.Select("unknown", null, null, "RemoteSigned") == "unknown", "malformed higher scope fell through");
            Check(!ExecutionPowerShellPolicy.Allows("fixture", () => throw new IOException("synthetic denied read"), _ => true), "policy read error admitted");
            string? changing = "RemoteSigned";
            Check(!ExecutionPowerShellPolicy.Allows("fixture", () => changing, _ => { changing = "AllSigned"; return true; }), "changed policy during origin read admitted");
        });
        Test("execution runner read-only policy argv never contains Execute or payload path", () =>
        {
            var (job, grant) = ExecutionFixture();
            var readOnly = Scn001Runner.Arguments(grant, job.Job.JobId, job.Job.Parameters, false);
            Check(readOnly.Take(4).SequenceEqual(new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File" }), "reviewed host flags changed");
            Check(readOnly[4] == grant.Profile.RunnerPath && !readOnly.Contains("-Execute") && !readOnly.Any(s => s.EndsWith("lab_update.ps1")), "policy probe attempted payload");
            var execute = Scn001Runner.Arguments(grant, job.Job.JobId, job.Job.Parameters, true);
            Check(execute[^1] == "-Execute" && execute.Count(s => s == "-Execute") == 1, "execution intent missing");
        });
        Test("execution policy unknown restricted audit and debug results fail closed", () =>
        {
            Check(ExecutionPolicyProof.PolicyAllowsResult(0x80000000), "explicit unrestricted result rejected");
            foreach (uint result in new uint[] { 0, 1, 0x80000004, 0x80000014, 0x8000001C, uint.MaxValue })
                Check(!ExecutionPolicyProof.PolicyAllowsResult(result), "unknown or restricted policy accepted");
            Check(ExecutionPolicyProof.PolicyAllowsResult(0x80000000, 0x40000), "fully trusted paired policy rejected");
            Check(!ExecutionPolicyProof.PolicyAllowsResult(0x80000000, 0), "AppLocker deny ignored");
            Check(!ExecutionPolicyProof.PolicyAllowsResult(0x80000004, 0x40000), "WDAC deny ignored");
        });
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || RuntimeInformation.ProcessArchitecture != Architecture.X64)
        { Console.WriteLine("SKIP execution native (requires Windows 10+/Server 2016+ x64)"); return; }
        Test("execution native per-file origin rejects payload MOTW without changing bytes or metadata", () =>
        {
            using var temp = new Scratch(); Directory.CreateDirectory(temp.Path);
            var runner = Path.Combine(temp.Path, "runner.ps1"); var payload = Path.Combine(temp.Path, "payload.ps1");
            File.WriteAllText(runner, "# inert runner"); File.WriteAllText(payload, "# inert payload");
            var bytes = File.ReadAllBytes(payload); var zone = payload + ":Zone.Identifier";
            Check(ExecutionPowerShellPolicy.LocalOrigin(runner) && ExecutionPowerShellPolicy.LocalOrigin(payload), "local scratch origin not established");
            File.WriteAllText(zone, "[ZoneTransfer]\r\nZoneId=3\r\n");
            Check(ExecutionPowerShellPolicy.LocalOrigin(runner) && !ExecutionPowerShellPolicy.LocalOrigin(payload), "payload Internet origin inherited runner authorization");
            Check(File.ReadAllBytes(payload).SequenceEqual(bytes) && File.ReadAllText(zone) == "[ZoneTransfer]\r\nZoneId=3\r\n", "origin check changed file or unblocked metadata");
            File.WriteAllText(zone, "unrecognized-origin");
            Check(!ExecutionPowerShellPolicy.LocalOrigin(payload), "malformed origin metadata accepted");
        });
        Test("execution native child excludes parent process execution policy override", async () =>
        {
            using var temp = new Scratch(); Directory.CreateDirectory(temp.Path);
            var previous = Environment.GetEnvironmentVariable("PSExecutionPolicyPreference");
            try
            {
                Environment.SetEnvironmentVariable("PSExecutionPolicyPreference", "synthetic-not-a-policy");
                var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "environment", Path.Combine(temp.Path, "marker")],
                    temp.Path, TimeSpan.FromSeconds(8), _ => Task.CompletedTask, _ => { }, CancellationToken.None);
                Check(result.Observation.ExitCode == 0 && result.Observation.CleanupSucceeded, "child inherited process policy override");
            }
            finally { Environment.SetEnvironmentVariable("PSExecutionPolicyPreference", previous); }
        });
        Test("execution native delayed preflight samples current monotonic and rejects expired interval before create", async () =>
        {
            using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); var marker = Path.Combine(temp.Path, "marker");
            var (grant, facts) = PreflightFixture(); var (job, _) = ExecutionFixture(grant);
            var utc = ExecutionCoordinator.Instant(job.Job.ExpiresAt).AddSeconds(-3); var mono = TimeSpan.Zero;
            var clock = new ExecutionClock(() => utc); clock.Observe(utc, utc, mono, mono);
            facts.BeforeRead = () => { facts.BeforeRead = null; mono += TimeSpan.FromSeconds(1.1); utc += TimeSpan.FromSeconds(1.1); };
            bool created = false;
            var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "exit", marker], temp.Path,
                TimeSpan.FromSeconds(5), _ => Task.CompletedTask, _ => created = true, CancellationToken.None,
                finalCheck: () => { if (!ExecutionPreflight.CheckBeforeLaunch(job.Job, grant, clock, () => mono, facts).Ready) throw new ConnectionException("execution_not_ready"); });
            Check(!created && result.Observation.StartedAt == null && !File.Exists(marker), "slow preflight used stale captured monotonic timestamp");
        });
        Test("execution native SCM callback cancellation awaits tree cleanup inside stop budget", () =>
        {
            using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); bool cleaned = false;
            var api = new ServiceBoundary { OnRunning = boundary => _ = Task.Run(async () => { await Task.Delay(1000); boundary.Control!(1); }) };
            var watch = Stopwatch.StartNew();
            var result = WindowsServiceHost.Run(temp.Path, api, async (_, token) =>
            {
                var native = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "tree", Path.Combine(temp.Path, "marker")],
                    temp.Path, TimeSpan.FromSeconds(15), _ => Task.CompletedTask, _ => { }, token);
                cleaned = native.Observation.CleanupSucceeded; return cleaned ? 0 : 3;
            });
            Check(result == 0 && cleaned && watch.Elapsed < TimeSpan.FromSeconds(20) && api.Statuses[^1].State == ServiceState.Stopped, "SCM stop raced cleanup or exceeded budget");
        });
        Test("execution native timeout leaves independent owned job alive", async () =>
        {
            using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); using var unrelatedStop = new CancellationTokenSource();
            var otherMarker = Path.Combine(temp.Path, "other");
            var other = WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "wait", otherMarker], temp.Path,
                TimeSpan.FromSeconds(15), _ => Task.CompletedTask, _ => { }, unrelatedStop.Token);
            try
            {
                var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "tree", Path.Combine(temp.Path, "target")], temp.Path,
                    TimeSpan.FromSeconds(3), _ => Task.CompletedTask, _ => { }, CancellationToken.None);
                Check(result.Observation.CleanupSucceeded && result.Observation.ExitCode == null && File.Exists(otherMarker) && !other.IsCompleted, "timeout crossed owned job boundary");
            }
            finally { unrelatedStop.Cancel(); Check((await other).Observation.CleanupSucceeded, "unrelated test cleanup failed"); }
        });
        Test("execution native attribute failure has zero create or resumed fallback", async () =>
        {
            foreach (nuint rejected in new nuint[] { 0x2000D, 0x20002 })
            {
                using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); var marker = Path.Combine(temp.Path, "marker"); bool created = false;
                var api = new NativeFaultBoundary { RejectAttribute = rejected };
                var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "exit", marker], temp.Path,
                    TimeSpan.FromSeconds(4), _ => Task.CompletedTask, _ => created = true, CancellationToken.None, api: api);
                Check(!created && !File.Exists(marker) && api.Resumes == 0 && result.Observation.StartedAt == null, "attribute error used fallback");
            }
        });
        Test("execution native unconfirmed query and output finalization remain unknown", async () =>
        {
            using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); var marker = Path.Combine(temp.Path, "marker");
            var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "exit", marker], temp.Path,
                TimeSpan.FromSeconds(4), _ => Task.CompletedTask, _ => { }, CancellationToken.None, api: new NativeFaultBoundary { FailQuery = true });
            Check(!result.Observation.CleanupSucceeded, "failed query claimed cleanup");
            result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "exit", marker], temp.Path,
                TimeSpan.FromSeconds(4), _ => Task.CompletedTask, _ => { }, CancellationToken.None,
                finalizeOutput: _ => throw new IOException("synthetic output failure"));
            Check(!result.Observation.CleanupSucceeded, "failed output claimed cleanup");
        });
        Test("execution native output cap and normal root exit terminate descendants", async () =>
        {
            using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); var marker = Path.Combine(temp.Path, "marker");
            var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "tree-exit", marker], temp.Path,
                TimeSpan.FromSeconds(8), _ => Task.CompletedTask, _ => { }, CancellationToken.None);
            Check(File.Exists(marker + ".grand") && result.Observation.CleanupSucceeded && result.Observation.ExitCode == 0, "normal root exit left descendant");
            var large = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "large", marker], temp.Path,
                TimeSpan.FromSeconds(8), _ => Task.CompletedTask, _ => { }, CancellationToken.None);
            Check(large.Observation.CleanupSucceeded && large.Output.Length == 1048576, "output not bounded or drained");
        });
        Test("execution native handle whitelist excludes an inheritable sentinel", async () =>
        {
            using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); var marker = Path.Combine(temp.Path, "marker");
            var security = new TestSecurity { Length = Marshal.SizeOf<TestSecurity>(), Inherit = true };
            var sentinel = CreateEventW(ref security, true, false, null); Check(sentinel != 0, "sentinel unavailable");
            try
            {
                var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "sentinel", marker, sentinel.ToString()], temp.Path,
                    TimeSpan.FromSeconds(8), _ => Task.CompletedTask, _ => { }, CancellationToken.None);
                Check(result.Observation.ExitCode == 0 && result.Observation.CleanupSucceeded && WaitForSingleObject(sentinel, 0) == 258, "non-stdio handle inherited");
            }
            finally { CloseHandle(sentinel); }
        });
        Test("execution native suspended atomic containment precedes marker and output", async () =>
        {
            RequireNative(); using var temp = new Scratch(); Directory.CreateDirectory(temp.Path);
            var marker = Path.Combine(temp.Path, "marker"); bool observed = false;
            var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "exit", marker], temp.Path,
                TimeSpan.FromSeconds(8), _ => Task.CompletedTask, creation =>
                { Check(!File.Exists(marker), "child ran before observed creation persisted"); Check(creation.CreationFileTime > 0, "creation identity absent"); observed = true; }, CancellationToken.None);
            Check(observed && File.Exists(marker) && result.Observation.ExitCode == 0 && result.Observation.CleanupSucceeded, "contained child did not finish");
            Check(System.Text.Encoding.UTF8.GetString(result.Output).Contains("inert-child"), "stdio absent");
        });
        Test("execution native journal callback failure never resumes child", async () =>
        {
            RequireNative(); using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); var marker = Path.Combine(temp.Path, "marker");
            var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "exit", marker], temp.Path,
                TimeSpan.FromSeconds(8), _ => Task.CompletedTask, _ => throw new IOException("synthetic durability failure"), CancellationToken.None);
            Check(!File.Exists(marker) && result.Observation.ExitCode == null, "failed persistence resumed child");
            Check(result.Observation.CleanupSucceeded, "suspended child tree not cleaned up");
        });
        Test("execution native cancellation terminates descendants within one deadline", async () =>
        {
            RequireNative(); using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); var marker = Path.Combine(temp.Path, "marker");
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(2)); var watch = Stopwatch.StartNew();
            var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "tree", marker], temp.Path,
                TimeSpan.FromSeconds(10), _ => Task.CompletedTask, _ => { }, stop.Token);
            Check(File.Exists(marker + ".grand") && result.Observation.CleanupSucceeded && result.Observation.ExitCode == null, "tree cancellation not confirmed");
            Check(watch.Elapsed < TimeSpan.FromSeconds(8), "additive stop timeout");
        });
        Test("execution native failed precreate and expired deadline create no child", async () =>
        {
            RequireNative(); using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); var marker = Path.Combine(temp.Path, "marker");
            var result = await WindowsExecutionNative.RunAsync(Environment.ProcessPath!, ["--execution-child", "exit", marker], temp.Path,
                TimeSpan.FromMilliseconds(100), async _ => await Task.Delay(150), _ => throw new Exception("unexpected create"), CancellationToken.None);
            Check(!File.Exists(marker) && result.Observation.StartedAt == null, "expired budget created process");
        });
    }
    private static void RequireNative()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || RuntimeInformation.ProcessArchitecture != Architecture.X64)
            throw new Exception("Required Windows 10+/Server 2016+ x64 native gate unavailable");
    }
    private sealed class NativeFaultBoundary : WindowsExecutionNative.NativeApi
    {
        public nuint RejectAttribute; public bool FailQuery; public int Resumes;
        internal override bool Attribute(nint list, nuint attribute, nint value, nuint bytes) =>
            attribute != RejectAttribute && base.Attribute(list, attribute, value, bytes);
        internal override uint Resume(nint thread) { Resumes++; return base.Resume(thread); }
        internal override bool Active(nint job, out uint count)
        { if (FailQuery) { count = uint.MaxValue; return false; } return base.Active(job, out count); }
    }
    private static async Task<int> ExecutionChild(string[] args)
    {
        if (args.Length is not (3 or 4)) return 2;
        File.WriteAllText(args[2], "inert"); Console.WriteLine("inert-child"); Console.Error.WriteLine("inert-stderr");
        if (args[1] == "exit") return 0;
        if (args[1] == "environment") return Environment.GetEnvironmentVariable("PSExecutionPolicyPreference") == null ? 0 : 4;
        if (args[1] == "sentinel") { SetEvent(nint.Parse(args[3])); return 0; }
        if (args[1] == "large") { Console.Write(new string('x', 3 * 1024 * 1024)); return 0; }
        if (args[1] is "tree" or "tree-exit")
        {
            var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
            start.ArgumentList.Add("--execution-child"); start.ArgumentList.Add("wait"); start.ArgumentList.Add(args[2] + ".grand");
            using var child = Process.Start(start) ?? throw new Exception("inert grandchild missing");
            while (!File.Exists(args[2] + ".grand")) await Task.Delay(10);
            if (args[1] == "tree-exit") return 0;
        }
        await Task.Delay(Timeout.Infinite); return 0;
    }
    [StructLayout(LayoutKind.Sequential)] private struct TestSecurity { public int Length; public nint Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern nint CreateEventW(ref TestSecurity attributes, [MarshalAs(UnmanagedType.Bool)] bool manual, [MarshalAs(UnmanagedType.Bool)] bool initial, string? name);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetEvent(nint handle);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(nint handle, uint milliseconds);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(nint handle);
}
