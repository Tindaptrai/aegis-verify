using System.Collections.Immutable;

namespace Aegis.Connection.Execution;

public sealed record ExecutionConfigurationPaths(string ProfilePath, string GrantPath, string SigningPublicKeyPath);

public static class AgentSupervisor
{
    public static Task<int> RunAsync(string stateDirectory, CancellationToken stop) => RunAsync(stateDirectory, null, stop);
    public static async Task<int> RunAsync(string stateDirectory, ExecutionConfigurationPaths? paths, CancellationToken stop)
    {
        if (paths == null) return await HeartbeatLoop.RunAsync(stateDirectory, stop);
        try
        {
            if (!OperatingSystem.IsWindows()) throw new ConnectionException("usage_invalid");
            using var store = StateStore.Acquire(stateDirectory);
            var identity = store.Read() ?? throw new ConnectionException("identity_missing");
            if (identity.Kind != "enrolled") throw new ConnectionException("enrollment_pending");
            using var client = new AgentClient(identity);
            Task<int> Heartbeat(CancellationToken token) => HeartbeatLoop.RunAsync(store, client, Task.Delay, () => DateTimeOffset.UtcNow, Random.Shared.NextDouble, token);
            ExecutionGrant grant;
            try { grant = ExecutionProfile.Load(paths.ProfilePath, paths.GrantPath, paths.SigningPublicKeyPath, identity); }
            catch (ConnectionException)
            {
                Console.Error.WriteLine("{\"error\":{\"code\":\"execution_not_ready\"}}");
                return await Heartbeat(stop);
            }
            var clock = new ExecutionClock(); var policy = new ExecutionPolicyProof(); var facts = new NativeExecutionFacts(policy.Allows);
            var transport = new ExecutionClient(client, grant, paths.SigningPublicKeyPath, clock);
            var journalDirectory = Path.Combine(stateDirectory, "execution"); var journal = new ExecutionJournal(journalDirectory);
            var runner = new Scn001Runner(journalDirectory, clock, facts);
            using var readinessGate = new SemaphoreSlim(1, 1);
            async Task<bool> Refresh(VerifiedExecutionJob? job, CancellationToken token)
            {
                await readinessGate.WaitAsync(token);
                try
                {
                    if (!policy.Allows(grant)) await policy.RefreshAsync(grant, token);
                    LocalReadiness Current()
                    {
                        var local = ExecutionPreflight.Check(grant, facts);
                        if (!clock.IsCertain(clock.MonotonicNow)) local = local with { Ready = false, BlockingCodes = local.BlockingCodes.Add("clock_uncertain").Distinct().ToImmutableArray() };
                        return local;
                    }
                    async Task Send(LocalReadiness local)
                    {
                        var request = new ReadinessRequest(ExecutionProtocol.Version, identity.DeviceId!, identity.Generation!.Value, grant.Installed.BindingId,
                            grant.Installed.BindingRevision, local.InstallationProfileSha256, local.ArtifactSetSha256, local.Ready, local.BlockingCodes);
                        var utc = DateTimeOffset.UtcNow; var sent = clock.MonotonicNow;
                        var raw = await transport.ReadinessAsync(request, token); var received = clock.MonotonicNow;
                        var ack = ExecutionProtocol.ReadinessAck(raw);
                        clock.Observe(ExecutionCoordinator.Instant(ack.ServerTime), utc, sent, received);
                    }
                    var first = Current(); await Send(first); var next = Current();
                    if (first.Ready != next.Ready || !first.BlockingCodes.SequenceEqual(next.BlockingCodes)) await Send(next);
                    return job == null ? Current().Ready : ExecutionPreflight.CheckBeforeLaunch(job.Job, grant, clock, () => clock.MonotonicNow, facts).Ready;
                }
                finally { readinessGate.Release(); }
            }
            async Task Reports(CancellationToken token)
            {
                while (true)
                {
                    var started = clock.MonotonicNow;
                    try { await Refresh(null, token); }
                    catch (ConnectionException e) when (e.Transient) { }
                    var remaining = TimeSpan.FromSeconds(15) - (clock.MonotonicNow - started);
                    if (remaining > TimeSpan.Zero) await Task.Delay(remaining, token);
                    token.ThrowIfCancellationRequested();
                }
            }
            var coordinator = new ExecutionCoordinator(Refresh);
            try { return await SuperviseAsync(Heartbeat, token => coordinator.RunAsync(identity, grant, transport, journal, runner, token), Reports, stop); }
            catch (ConnectionException e) when (e.Code == "identity_denied")
            {
                // All loops have stopped: heartbeat can no longer clear this terminal failure.
                store.MarkFailure("identity_denied"); return 3;
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
        catch (Exception e) when (e is ConnectionException or IOException or UnauthorizedAccessException or ArgumentException)
        { Console.Error.WriteLine("{\"error\":{\"code\":\"execution_unavailable\"}}"); return 3; }
    }
    internal static async Task<int> SuperviseAsync(Func<CancellationToken, Task<int>> heartbeat,
        Func<CancellationToken, Task> execution, Func<CancellationToken, Task> readiness, CancellationToken stop)
    {
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stop);
        var hb = Task.Run(() => heartbeat(lifetime.Token));
        var work = Task.Run(() => execution(lifetime.Token));
        var reports = Task.Run(() => readiness(lifetime.Token));
        await Task.WhenAny(hb, work, reports);
        await lifetime.CancelAsync();
        try { await Task.WhenAll(hb, work, reports); }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        {
            // Prefer a real denial/fault over a sibling's expected cancellation.
            foreach (var task in new Task[] { hb, work, reports })
                if (task.Exception is { } fault) throw fault.InnerException ?? fault;
        }
        return hb.IsCompletedSuccessfully ? hb.Result : stop.IsCancellationRequested ? 0 : 3;
    }
}
