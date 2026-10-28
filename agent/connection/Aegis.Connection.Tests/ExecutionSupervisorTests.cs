using Aegis.Connection;
using Aegis.Connection.Execution;

internal static partial class Program
{
    private static void ExecutionSupervisorTests()
    {
        Test("execution supervisor presence-only preserves identity missing diagnostic", async () =>
        {
            using var temp = new Scratch(); using var capture = new StringWriter(); var previous = Console.Error;
            try
            {
                Console.SetError(capture);
                var result = await AgentSupervisor.RunAsync(temp.Path, CancellationToken.None);
                Check(result == 3 && capture.ToString().Contains("identity_missing") && !capture.ToString().Contains("execution_unavailable"), "presence-only failure changed");
            }
            finally { Console.SetError(previous); }
        });
        Test("execution diagnostics distinguishes active lock drained journal and unresolved recovery", () =>
        {
            using var temp = new Scratch();
            using (var store = StateStore.Acquire(temp.Path))
            {
                _ = new ExecutionJournal(Path.Combine(temp.Path, "execution"));
                var active = ExecutionDiagnostics.ReadStatus(temp.Path);
                Check(active.SupervisorState == "running" && active.DrainState == "active" && active.PendingStartCount == null, "active snapshot claimed drained");
            }
            var empty = ExecutionDiagnostics.ReadStatus(temp.Path);
            Check(empty.SupervisorState == "stopped" && empty.DrainState == "drained" && empty.PendingStartCount == 0, "empty stopped journal not drained");
            var (job, _) = ExecutionFixture(); var journal = new ExecutionJournal(Path.Combine(temp.Path, "execution"));
            journal.Transition(job.Job.JobId, null, ExecutionJournalEntry.Received(job));
            var pending = ExecutionDiagnostics.ReadStatus(temp.Path);
            Check(pending.DrainState == "recovery_required" && pending.PendingStartCount == 1, "pending attempt hidden");
            var raw = System.Text.Json.JsonSerializer.Serialize(pending);
            Check(!raw.Contains(job.Job.JobId) && !raw.Contains(temp.Path), "diagnostic leaked identity/path");
        });
        Test("execution diagnostics configuration validation never substitutes administrator for service readiness", () =>
        {
            var (grant, facts) = PreflightFixture(); facts.Policy = false; facts.Telemetry = false;
            var result = ExecutionPreflight.CheckConfiguration(grant, facts);
            Check(result.ConfigurationValid && result.ServiceReadiness == "not_evaluated", "static validation conflated policy readiness");
            Check(!ExecutionPreflight.Check(grant, facts).Ready, "administrator validation established service readiness");
            facts.Files[grant.Profile.RunnerPath] = "drift"u8.ToArray();
            Check(!ExecutionPreflight.CheckConfiguration(grant, facts).ConfigurationValid, "configuration artifact drift accepted");
        });
        Test("execution supervisor heartbeat independent and denial cancels owned work", async () =>
        {
            foreach (bool cancelDuringHandshake in new[] { true, false })
            {
                var handshake = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var executionEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var readinessEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                bool cleaned = false; bool readinessStopped = false;
                var result = await AgentSupervisor.SuperviseAsync(async token =>
                {
                    if (!cancelDuringHandshake) handshake.SetResult();
                    await Task.WhenAll(executionEntered.Task, readinessEntered.Task).WaitAsync(token);
                    return 3;
                }, async token =>
                {
                    try
                    {
                        executionEntered.SetResult();
                        await handshake.Task.WaitAsync(token);
                        await Task.Delay(Timeout.Infinite, token);
                    }
                    finally { cleaned = true; }
                }, async token =>
                {
                    readinessEntered.SetResult();
                    try { await Task.Delay(Timeout.Infinite, token); }
                    catch (OperationCanceledException) when (token.IsCancellationRequested) { readinessStopped = true; }
                }, CancellationToken.None);
                Check(result == 3 && cleaned && readinessStopped,
                    $"identity failure did not await bounded cleanup (handshake_pending={cancelDuringHandshake})");
            }
        });
        Test("execution diagnostics missing state does not create directory and never reports ready", async () =>
        {
            using var temp = new Scratch();
            var result = ExecutionDiagnostics.ReadStatus(temp.Path);
            Check(result.JournalState == "absent" && result.DrainState == "unknown" && !Directory.Exists(temp.Path), "status mutated missing state");
            var code = await Aegis.Connection.Program.RunAsync(["execution-validate", "--state-dir", temp.Path,
                "--execution-profile", temp.Path + "p", "--execution-grant", temp.Path + "g", "--execution-key", temp.Path + "k"], () => throw new Exception("prompted"), CancellationToken.None);
            Check(code == (OperatingSystem.IsWindows() ? 3 : 2) && !Directory.Exists(temp.Path), "invalid validation created identity/state");
        });
        Test("execution CLI triple partial forbidden and status remains read only", async () =>
        {
            using var temp = new Scratch();
            foreach (var command in new[] { "run", "service", "execution-validate" })
            {
                var code = await Aegis.Connection.Program.RunAsync([command, "--state-dir", temp.Path, "--execution-profile", "missing"], () => "", CancellationToken.None);
                Check(code == 2 && !Directory.Exists(temp.Path), "partial configuration created state");
            }
        });
    }
}
