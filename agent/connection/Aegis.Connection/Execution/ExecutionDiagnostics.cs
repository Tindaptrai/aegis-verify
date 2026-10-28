using System.Collections.Immutable;

namespace Aegis.Connection.Execution;

public sealed record ExecutionConfigurationStatus(int SchemaVersion, bool ConfigurationValid, string ServiceReadiness, ImmutableArray<string> BlockingCodes);
public sealed record ExecutionStatus(int SchemaVersion, string JournalState, string SupervisorState, string DrainState,
    int? PendingStartCount, int? PendingReceiptCount, int? UnknownCount);

public static class ExecutionDiagnostics
{
    public static ExecutionConfigurationStatus ValidateConfiguration(string stateDirectory, ExecutionConfigurationPaths paths)
    {
        if (!OperatingSystem.IsWindows()) return new(1, false, "not_evaluated", ["unsupported_platform"]);
        try
        {
            var identity = StateStore.ReadExisting(stateDirectory);
            var grant = ExecutionProfile.Load(paths.ProfilePath, paths.GrantPath, paths.SigningPublicKeyPath, identity);
            using var key = ExecutionProfile.LoadSigningKey(paths.SigningPublicKeyPath, grant);
            return ExecutionPreflight.CheckConfiguration(grant, new NativeExecutionFacts());
        }
        catch (Exception e) when (e is ConnectionException or IOException or UnauthorizedAccessException or ArgumentException)
        { return new(1, false, "not_evaluated", ["profile_mismatch"]); }
    }
    public static ExecutionStatus ReadStatus(string stateDirectory)
    {
        try
        {
            if (!Path.IsPathFullyQualified(stateDirectory)) throw new ConnectionException("state_invalid");
            PrivatePaths.NoLinks(stateDirectory);
            if (!Directory.Exists(stateDirectory)) return new(1, "absent", "unknown", "unknown", null, null, null);
            PrivatePaths.Verify(stateDirectory, true);
            var gate = Path.Combine(stateDirectory, "process.lock"); PrivatePaths.Verify(gate, false);
            FileStream held;
            try { held = new FileStream(gate, FileMode.Open, FileAccess.Read, FileShare.None); }
            catch (IOException) { return new(1, "unknown", "running", "active", null, null, null); }
            using (held)
            {
                var path = Path.Combine(stateDirectory, "execution"); PrivatePaths.NoLinks(path);
                if (!Directory.Exists(path)) return new(1, "absent", "stopped", "unknown", null, null, null);
                var entries = ExecutionJournal.InspectExisting(path);
                var starts = entries.Count(e => e.Phase is not ("terminal" or "accepted"));
                var receipts = entries.Count(e => e.Phase == "terminal");
                var unknown = entries.Count(e => e.Receipt != null && ExecutionProtocol.Decode<ExecutionReceipt>(ExecutionJournal.Raw(e.Receipt)).State == "execution_unknown");
                return new(1, "valid", "stopped", starts > 0 || unknown > 0 ? "recovery_required" : receipts > 0 ? "pending_receipt" : "drained", starts, receipts, unknown);
            }
        }
        catch (Exception e) when (e is ConnectionException or IOException or UnauthorizedAccessException or ArgumentException)
        { return new(1, "invalid", "unknown", "unknown", null, null, null); }
    }
}
