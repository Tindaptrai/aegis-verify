using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

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
    private readonly IExecutionFacts facts;
    private readonly Func<string, bool> filePolicy;
    private readonly Func<string, bool> powerShellPolicy;
    private readonly Func<ExecutionGrant, CancellationToken, Task<bool>> runnerProof;
    internal ExecutionPolicyProof() : this(new NativeExecutionFacts(), FilePolicyAllows, RunReadOnlyAsync,
        path => ExecutionPowerShellPolicy.Allows(path, ExecutionPowerShellPolicy.ReadEffectivePolicy, ExecutionPowerShellPolicy.LocalOrigin)) { }
    internal ExecutionPolicyProof(IExecutionFacts facts, Func<string, bool> filePolicy,
        Func<ExecutionGrant, CancellationToken, Task<bool>> runnerProof, Func<string, bool> powerShellPolicy)
    { this.facts = facts; this.filePolicy = filePolicy; this.runnerProof = runnerProof; this.powerShellPolicy = powerShellPolicy; }
    private long observed;
    private string? profile;
    internal bool Allows(ExecutionGrant grant)
    {
        if (Volatile.Read(ref profile) != grant.Installed.InstallationProfileSha256 ||
            Stopwatch.GetElapsedTime(Interlocked.Read(ref observed)) > TimeSpan.FromSeconds(15)) return false;
        try { return AllFilesAllow(grant); }
        catch (Exception e) when (e is ConnectionException or IOException or UnauthorizedAccessException or DllNotFoundException or EntryPointNotFoundException or ArgumentException) { return false; }
    }
    private static string[] PolicyFiles(ExecutionGrant grant) => [grant.Profile.RunnerPath,
        Path.Combine(grant.Profile.KitDirectory, "lab_update.ps1"), Path.Combine(grant.Profile.KitDirectory, "maintenance_check.ps1")];
    private bool AllFilesAllow(ExecutionGrant grant) => PolicyFiles(grant).All(path => powerShellPolicy(path) && filePolicy(path));
    internal async Task<bool> RefreshAsync(ExecutionGrant grant, CancellationToken stop)
    {
        await gate.WaitAsync(stop);
        try
        {
            Volatile.Write(ref profile, null);
            if (!facts.Supported || !facts.ServiceIdentity) return false;
            ExecutionPreflight.CheckArtifacts(grant, facts);
            // Zero flags retains signature and SaferIdentifyLevel validation. Unknown,
            // enforced, audit and debug policy states are conservatively not ready.
            if (!AllFilesAllow(grant)) return false;
            if (!await runnerProof(grant, stop) || !AllFilesAllow(grant)) return false;
            Interlocked.Exchange(ref observed, Stopwatch.GetTimestamp());
            Volatile.Write(ref profile, grant.Installed.InstallationProfileSha256); return true;
        }
        catch (Exception e) when (e is ConnectionException or IOException or UnauthorizedAccessException or DllNotFoundException or EntryPointNotFoundException or ArgumentException)
        { return false; }
        finally { gate.Release(); }
    }
    private static async Task<bool> RunReadOnlyAsync(ExecutionGrant grant, CancellationToken stop)
    {
        var facts = new NativeExecutionFacts();
        var result = await WindowsExecutionNative.RunAsync(facts.PowerShellPath,
            Scn001Runner.Arguments(grant, Guid.NewGuid().ToString(), new("A", "baseline", grant.Profile.RulePins.Baseline), false),
            grant.Profile.KitDirectory, TimeSpan.FromSeconds(8), _ => Task.CompletedTask, _ => { }, stop);
        return result.Observation.ExitCode == 0 && result.Observation.CleanupSucceeded &&
            Encoding.UTF8.GetString(result.Output).Replace("\r\n", "\n") == "{\"kind\":\"safe_demo_preflight\",\"status\":\"ready\",\"executed\":false}\n";
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

internal static class ExecutionPowerShellPolicy
{
    // Deliberately support only the local-file branches where PowerShell does not
    // consult signatures or publisher prompts. Never emulate those decisions.
    internal static bool Allows(string path, Func<string?> policy, Func<string, bool> localOrigin)
    {
        try
        {
            var before = policy();
            if (!string.Equals(before, "RemoteSigned", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(before, "Unrestricted", StringComparison.OrdinalIgnoreCase)) return false;
            return localOrigin(path) && string.Equals(before, policy(), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException or COMException)
        { return false; }
    }
    internal static string? Select(string? machinePolicy, string? userPolicy, string? currentUser, string? localMachine) =>
        machinePolicy ?? userPolicy ?? currentUser ?? localMachine;
    internal static string? ReadEffectivePolicy()
    {
        if (!OperatingSystem.IsWindows()) return "unknown";
        // Windows PowerShell 5.1, Microsoft.PowerShell shell, native 64-bit view.
        // Process policy is absent in WindowsExecutionNative's explicit environment.
        // No default/Undefined interpretation: absence at every scope is unknown.
        return Select(ReadScope(RegistryHive.LocalMachine, true), ReadScope(RegistryHive.CurrentUser, true),
            ReadScope(RegistryHive.CurrentUser, false), ReadScope(RegistryHive.LocalMachine, false));
    }
    [SupportedOSPlatform("windows")]
    private static string? ReadScope(RegistryHive hive, bool group)
    {
        using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
        using var key = root.OpenSubKey(group ? @"Software\Policies\Microsoft\Windows\PowerShell" :
            @"Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", false);
        if (key == null) return null;
        if (group)
        {
            var enabled = key.GetValue("EnableScripts", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (enabled == null) return null;
            if (key.GetValueKind("EnableScripts") != RegistryValueKind.DWord || enabled is not int flag) return "unknown";
            if (flag == 0) return "Restricted";
            if (flag != 1) return "unknown";
        }
        var value = key.GetValue("ExecutionPolicy", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (value == null) return group ? "unknown" : null;
        return key.GetValueKind("ExecutionPolicy") == RegistryValueKind.String && value is string policy ? policy : "unknown";
    }
    internal static bool LocalOrigin(string path)
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            ExecutionProfile.LocalPath(path); PrivatePaths.NoLinks(path);
            if (new DriveInfo(Path.GetPathRoot(path)!).DriveType != DriveType.Fixed) return false;
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            // Any declared origin is unsupported, including empty/malformed streams.
            // Missing stream is the only accepted failure; access/IO errors deny.
            try { using var zone = new FileStream(path + ":Zone.Identifier", FileMode.Open, FileAccess.Read, FileShare.Read); return false; }
            catch (FileNotFoundException e) when ((e.HResult & 0xffff) == 2) { }
            if (CoInternetCreateSecurityManager(0, out var manager, 0) != 0 || manager == null) return false;
            try
            {
                // ISFILE | REQUIRESAVEDFILECHECK | DONT_UNESCAPE | DONT_USE_CACHE.
                // Retain actual zone mappings; never suppress origin checks.
                return manager.MapUrlToZone(path, out var zone, 0x1c02) == 0 && zone == 0;
            }
            finally { Marshal.FinalReleaseComObject(manager); }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or
            System.Security.SecurityException or COMException or DllNotFoundException or EntryPointNotFoundException)
        { return false; }
    }
    [ComImport, Guid("79EAC9EE-BAF9-11CE-8C82-00AA004BA90B"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IInternetSecurityManager
    {
        [PreserveSig] int SetSecuritySite(nint site);
        [PreserveSig] int GetSecuritySite(out nint site);
        [PreserveSig] int MapUrlToZone([MarshalAs(UnmanagedType.LPWStr)] string url, out uint zone, uint flags);
    }
    [DllImport("urlmon.dll", ExactSpelling = true)]
    private static extern int CoInternetCreateSecurityManager(nint provider, [MarshalAs(UnmanagedType.Interface)] out IInternetSecurityManager manager, uint reserved);
}
