using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Aegis.Connection.Execution;

public sealed class Scn001Runner : IExecutionRunner, IExecutionLifecycleRunner
{
    private readonly string journalDirectory;
    private readonly ExecutionClock clock;
    private readonly IExecutionFacts facts;
    private Func<CancellationToken, Task>? beforeCreate;
    private Action<ExecutionCreation>? observedCreated;
    internal Scn001Runner(string journalDirectory, ExecutionClock clock, IExecutionFacts facts)
    { this.journalDirectory = journalDirectory; this.clock = clock; this.facts = facts; }
    void IExecutionLifecycleRunner.ConfigureLifecycle(Func<CancellationToken, Task> before, Action<ExecutionCreation> created)
    { beforeCreate = before; observedCreated = created; }
    public async Task<ExecutionObservation> RunAsync(VerifiedExecutionJob job, ExecutionGrant grant, CancellationToken stop)
    {
        var elapsed = Stopwatch.StartNew();
        if (beforeCreate == null || observedCreated == null) throw new ConnectionException("execution_invalid");
        var before = beforeCreate; var created = observedCreated; beforeCreate = null; observedCreated = null;
        var run = Path.Combine(grant.Profile.RunDirectory, job.Job.JobId);
        ExecutionProfile.LocalPath(run, 206);
        if (Directory.Exists(run) || File.Exists(run)) throw new ConnectionException("execution_output_exists");
        PrivatePaths.Verify(journalDirectory, true);
        using var output = PrivatePaths.CreateFile(Path.Combine(journalDirectory, job.Job.JobId + ".log"));
        void FinalCheck()
        {
            // Repeat current host/artifact/policy and whole clock interval immediately before create/resume.
            if (!ExecutionPreflight.CheckBeforeLaunch(job.Job, grant, clock, () => clock.MonotonicNow, facts).Ready)
                throw new ConnectionException("execution_not_ready");
        }
        var result = await WindowsExecutionNative.RunAsync(facts.PowerShellPath, Arguments(grant, job.Job.JobId, job.Job.Parameters, true),
            grant.Profile.KitDirectory, TimeSpan.FromSeconds(job.Job.TimeoutSeconds) - elapsed.Elapsed, before, created, stop, FinalCheck,
            bytes => { output.Write(bytes); output.Flush(true); });
        return result.Observation;
    }
    internal static string[] Arguments(ExecutionGrant grant, string jobId, ExecutionParameters parameters, bool execute)
    {
        if (!Protocol.Uuid(jobId)) throw new ConnectionException("execution_invalid");
        var p = grant.Profile;
        var args = new List<string> { "-NoLogo", "-NoProfile", "-NonInteractive", "-File", p.RunnerPath,
            "-KitDirectory", p.KitDirectory, "-RunDirectory", Path.Combine(p.RunDirectory, jobId), "-RunId", jobId,
            "-RunLabel", parameters.RunLabel, "-ExpectedComputerName", p.ExpectedComputerName,
            "-AppliedRuleRevision", parameters.RuleRevision, "-AppliedRuleSha256", parameters.RuleSha256 };
        if (execute) args.Add("-Execute");
        return args.ToArray();
    }
}

// Private, short-lived proof; nothing from it is a detection event or execution receipt.
internal sealed class ExecutionPolicyProof
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private long observed;
    private string? profile;
    internal bool Allows(ExecutionGrant grant)
    {
        if (Volatile.Read(ref profile) != grant.Installed.InstallationProfileSha256 ||
            Stopwatch.GetElapsedTime(Interlocked.Read(ref observed)) > TimeSpan.FromSeconds(15)) return false;
        try { return PolicyFiles(grant).All(FilePolicyAllows); }
        catch (Exception e) when (e is ConnectionException or IOException or UnauthorizedAccessException or DllNotFoundException or EntryPointNotFoundException or ArgumentException) { return false; }
    }
    private static string[] PolicyFiles(ExecutionGrant grant) => [grant.Profile.RunnerPath,
        Path.Combine(grant.Profile.KitDirectory, "lab_update.ps1"), Path.Combine(grant.Profile.KitDirectory, "maintenance_check.ps1")];
    internal async Task<bool> RefreshAsync(ExecutionGrant grant, CancellationToken stop)
    {
        await gate.WaitAsync(stop);
        try
        {
            Volatile.Write(ref profile, null);
            var facts = new NativeExecutionFacts();
            if (!facts.Supported || !facts.ServiceIdentity) return false;
            ExecutionPreflight.CheckArtifacts(grant, facts);
            // Zero flags retains signature and SaferIdentifyLevel validation. Unknown,
            // enforced, audit and debug policy states are conservatively not ready.
            foreach (var path in PolicyFiles(grant))
                if (!FilePolicyAllows(path)) return false;
            var id = Guid.NewGuid().ToString();
            var result = await WindowsExecutionNative.RunAsync(facts.PowerShellPath,
                Scn001Runner.Arguments(grant, id, new("A", "baseline", grant.Profile.RulePins.Baseline), false),
                grant.Profile.KitDirectory, TimeSpan.FromSeconds(8), _ => Task.CompletedTask, _ => { }, stop);
            if (result.Observation.ExitCode != 0 || !result.Observation.CleanupSucceeded ||
                Encoding.UTF8.GetString(result.Output).Replace("\r\n", "\n") != "{\"kind\":\"safe_demo_preflight\",\"status\":\"ready\",\"executed\":false}\n") return false;
            Interlocked.Exchange(ref observed, Stopwatch.GetTimestamp());
            Volatile.Write(ref profile, grant.Installed.InstallationProfileSha256); return true;
        }
        catch (Exception e) when (e is ConnectionException or IOException or UnauthorizedAccessException or DllNotFoundException or EntryPointNotFoundException or ArgumentException)
        { return false; }
        finally { gate.Release(); }
    }
    internal static bool FilePolicyAllows(string path)
    {
        if (!OperatingSystem.IsWindows()) return false;
        ExecutionProfile.VerifyImmutable(path, false);
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var host = new WldpHost { Revision = 1, HostId = 4, Source = path, File = file.SafeFileHandle.DangerousGetHandle() };
        if (WldpGetLockdownPolicy(ref host, out var policy, 0) != 0 || !PolicyAllowsResult(policy)) return false;
        var properties = new SaferProperties { Size = (uint)Marshal.SizeOf<SaferProperties>(), Flags = 1 | 4 | 8,
            ImagePath = path, File = file.SafeFileHandle.DangerousGetHandle(), Hash = new byte[64], UiChoice = 2 };
        // Match PowerShell's script-specific AppLocker query; never calculate a new
        // token, set policy, record a synthetic event, or suppress a denial.
        if (!SaferIdentifyLevel(1, ref properties, out var level, "SCRIPT")) return false;
        try { return SaferGetLevelInformation(level, 1, out var levelId, 4, out var size) && size == 4 && PolicyAllowsResult(policy, levelId); }
        finally { SaferCloseLevel(level); }
    }
    internal static bool PolicyAllowsResult(uint result) => result == 0x80000000;
    internal static bool PolicyAllowsResult(uint result, uint saferLevel) => PolicyAllowsResult(result) && saferLevel == 0x40000;
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WldpHost { public uint Revision, HostId; [MarshalAs(UnmanagedType.LPWStr)] public string Source; public nint File; }
    [DllImport("wldp.dll", ExactSpelling = true, CharSet = CharSet.Unicode)] private static extern int WldpGetLockdownPolicy(ref WldpHost host, out uint policy, uint flags);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SaferProperties
    {
        public uint Size, Flags; [MarshalAs(UnmanagedType.LPWStr)] public string ImagePath; public nint File; public uint Zone;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)] public byte[] Hash; public uint HashSize; public long ImageSize;
        public uint Algorithm; public nint ByteBlock, ParentWindow; public uint UiChoice;
    }
    [DllImport("advapi32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SaferIdentifyLevel(uint count, ref SaferProperties properties, out nint level, [MarshalAs(UnmanagedType.LPWStr)] string type);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SaferGetLevelInformation(nint level, uint kind, out uint value, uint size, out uint returned);
    [DllImport("advapi32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SaferCloseLevel(nint level);
}
