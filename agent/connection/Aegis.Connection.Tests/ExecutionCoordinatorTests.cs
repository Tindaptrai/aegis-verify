using Aegis.Connection;
using Aegis.Connection.Execution;

internal static partial class Program
{
    private static void ExecutionCoordinatorTests()
    {
        Test("execution coordinator cancellation after lost start ack spools unknown without launch", async () =>
        {
            using var temp = new Scratch(); var (job, grant) = ExecutionFixture(); var journal = new ExecutionJournal(temp.Path);
            using var stop = new CancellationTokenSource(); var transport = new ExecutionTransportDouble(job) { LoseStart = true };
            var runner = new ExecutionRunnerDouble(journal);
            var coordinator = new ExecutionCoordinator((_, _) => Task.FromResult(true), (_, token) => { stop.Cancel(); return Task.FromCanceled(token); });
            await coordinator.AttemptAsync(job, grant, transport, journal, runner, stop.Token);
            var entry = journal.Entries().Single(); var receipt = ExecutionProtocol.Decode<ExecutionReceipt>(Convert.FromBase64String(entry.Receipt!));
            Check(entry.Phase == "terminal" && runner.Runs == 0 && transport.Receipts.Count == 0 && receipt.StartedAt == null && !receipt.CleanupSucceeded, "cancelled ambiguous start launched or invented cleanup");
        });
        Test("execution coordinator accepted unknown retains tombstone but permits distinct authorized lease", async () =>
        {
            using var temp = new Scratch(); var (job, grant) = ExecutionFixture(); var journal = new ExecutionJournal(temp.Path);
            var entry = ExecutionJournalEntry.Received(job); journal.Transition(entry.JobId, null, entry);
            var start = new StartRequest(ExecutionProtocol.Version, job.Job.DeviceId, 1, job.Job.BindingId, 1, Guid.NewGuid().ToString(), job.JobSha256);
            journal.Transition(entry.JobId, "received", entry with { Phase = "start_requested", StartRequest = Convert.ToBase64String(ExecutionProtocol.SerializeStart(start)) });
            var coordinator = new ExecutionCoordinator((_, _) => Task.FromResult(true), (_, _) => Task.CompletedTask);
            await coordinator.RecoverAsync(journal, new ExecutionTransportDouble(job), CancellationToken.None);
            var old = journal.Entries().Single(); var runner = new ExecutionRunnerDouble(journal);
            var (next, nextGrant) = ExecutionFixture(grant); var transport = new ExecutionTransportDouble(next);
            await coordinator.AttemptAsync(next, nextGrant, transport, journal, runner, CancellationToken.None);
            await coordinator.AttemptAsync(job, grant, transport, journal, runner, CancellationToken.None);
            Check(runner.Runs == 1 && journal.Entries().Count == 2 && journal.Entries().Single(e => e.JobId == job.Job.JobId) == old, "new authority blocked or old tombstone replayed");
        });
        Test("execution coordinator lost start ack retries same bytes and launches once after durable intent", async () =>
        {
            using var temp = new Scratch(); var (job, grant) = ExecutionFixture(); var journal = new ExecutionJournal(temp.Path);
            var transport = new ExecutionTransportDouble(job) { LoseStart = true, LoseReceipt = true };
            var runner = new ExecutionRunnerDouble(journal);
            var coordinator = new ExecutionCoordinator((_, _) => Task.FromResult(true), (_, _) => Task.CompletedTask);
            await coordinator.AttemptAsync(job, grant, transport, journal, runner, CancellationToken.None);
            Check(runner.Runs == 1 && journal.Entries().Single().Phase == "accepted", "attempt failed to finish once");
            Check(transport.Starts.Count == 2 && transport.Starts[0].SequenceEqual(transport.Starts[1]), "start retry changed bytes");
            Check(transport.Receipts.Count == 2 && transport.Receipts[0].SequenceEqual(transport.Receipts[1]), "receipt retry changed bytes");
            await coordinator.AttemptAsync(job, grant, transport, journal, runner, CancellationToken.None);
            Check(runner.Runs == 1, "duplicate envelope launched twice");
        });
        Test("execution coordinator every uncertain restart spools unknown never launches", async () =>
        {
            foreach (var phase in new[] { "start_requested", "authorized", "launch_intent", "launched", "terminal" })
            {
                using var temp = new Scratch(); var (job, grant) = ExecutionFixture(); var journal = new ExecutionJournal(temp.Path);
                var entry = ExecutionJournalEntry.Received(job); journal.Transition(entry.JobId, null, entry);
                var start = new StartRequest(ExecutionProtocol.Version, job.Job.DeviceId, 1, job.Job.BindingId, 1, Guid.NewGuid().ToString(), job.JobSha256);
                entry = entry with { Phase = "start_requested", StartRequest = Convert.ToBase64String(ExecutionProtocol.SerializeStart(start)) };
                journal.Transition(entry.JobId, "received", entry);
                if (phase != "start_requested")
                {
                    entry = entry with { Phase = "authorized", StartAck = Convert.ToBase64String(ExecutionProtocol.CanonicalBytes(new StartAcknowledgment(ExecutionProtocol.Version, entry.JobId, start.StartRequestId, entry.JobSha256, true))) };
                    journal.Transition(entry.JobId, "start_requested", entry);
                }
                if (phase is "launch_intent" or "launched" or "terminal") { journal.Transition(entry.JobId, entry.Phase, entry with { Phase = "launch_intent" }); entry = journal.Entries().Single(); }
                if (phase is "launched" or "terminal") { journal.Transition(entry.JobId, entry.Phase, entry with { Phase = "launched", Creation = new(1234, 1000, 100, DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")) }); entry = journal.Entries().Single(); }
                if (phase == "terminal")
                {
                    var receipt = ExecutionCoordinator.Unknown(entry, DateTimeOffset.UtcNow);
                    journal.Transition(entry.JobId, "launched", entry with { Phase = "terminal", Receipt = Convert.ToBase64String(receipt) });
                }
                var before = journal.Entries().Single().Receipt; var transport = new ExecutionTransportDouble(job);
                var coordinator = new ExecutionCoordinator((_, _) => Task.FromResult(true), (_, _) => Task.CompletedTask);
                await coordinator.RecoverAsync(journal, transport, CancellationToken.None);
                var after = journal.Entries().Single(); var receiptAfter = ExecutionProtocol.Decode<ExecutionReceipt>(Convert.FromBase64String(after.Receipt!));
                Check(after.Phase == "accepted" && receiptAfter.State == "execution_unknown" && !receiptAfter.CleanupSucceeded, "restart claimed execution or cleanup");
                Check(transport.Starts.Count == 0 && (before == null || before == after.Receipt), "restart authorized or rewrote terminal receipt");
                Check(phase is "launched" or "terminal" || receiptAfter.StartedAt == null, "restart invented start");
            }
        });
        Test("execution coordinator mismatched ack never resumes or admits another job", async () =>
        {
            using var temp = new Scratch(); var (job, grant) = ExecutionFixture(); var journal = new ExecutionJournal(temp.Path);
            var transport = new ExecutionTransportDouble(job) { WrongAck = true }; var runner = new ExecutionRunnerDouble(journal);
            var coordinator = new ExecutionCoordinator((_, _) => Task.FromResult(true), (_, _) => Task.CompletedTask);
            await coordinator.AttemptAsync(job, grant, transport, journal, runner, CancellationToken.None);
            Check(runner.Runs == 0 && ExecutionProtocol.Decode<ExecutionReceipt>(Convert.FromBase64String(journal.Entries().Single().Receipt!)).State == "execution_unknown", "bad ack authorized launch");
        });
    }
    private sealed class ExecutionTransportDouble(VerifiedExecutionJob job) : IExecutionTransport
    {
        public bool LoseStart, LoseReceipt, WrongAck;
        public List<byte[]> Starts { get; } = []; public List<byte[]> Receipts { get; } = [];
        public Task<byte[]> ReadinessAsync(ReadinessRequest request, CancellationToken stop) => throw new NotSupportedException();
        public Task<VerifiedExecutionJob?> PollAsync(PollRequest request, CancellationToken stop) => Task.FromResult<VerifiedExecutionJob?>(job);
        public Task<byte[]> StartAsync(string jobId, StartRequest request, byte[] exact, CancellationToken stop)
        {
            Starts.Add((byte[])exact.Clone()); if (LoseStart && Starts.Count == 1) throw new ConnectionException("network_unavailable", true);
            return Task.FromResult(ExecutionProtocol.CanonicalBytes(new StartAcknowledgment(ExecutionProtocol.Version, WrongAck ? Guid.NewGuid().ToString() : jobId, request.StartRequestId, request.JobSha256, true)));
        }
        public Task<byte[]> ReceiptAsync(ExecutionReceipt request, byte[] exact, CancellationToken stop)
        {
            Receipts.Add((byte[])exact.Clone()); if (LoseReceipt && Receipts.Count == 1) throw new ConnectionException("network_unavailable", true);
            return Task.FromResult(ExecutionProtocol.CanonicalBytes(new ReceiptAcknowledgment(ExecutionProtocol.Version, request.JobId, request.ReceiptId, request.JobSha256, true)));
        }
    }
    private sealed class ExecutionRunnerDouble(ExecutionJournal journal) : IExecutionRunner, IExecutionLifecycleRunner
    {
        private Func<CancellationToken, Task> before = null!; private Action<ExecutionCreation> created = null!;
        public int Runs;
        public void ConfigureLifecycle(Func<CancellationToken, Task> beforeCreate, Action<ExecutionCreation> observedCreated) { before = beforeCreate; created = observedCreated; }
        public async Task<ExecutionObservation> RunAsync(VerifiedExecutionJob job, ExecutionGrant grant, CancellationToken stop)
        {
            Check(journal.Entries().Single(e => e.JobId == job.Job.JobId).Phase == "launch_intent", "native attempt preceded durable intent");
            await before(stop); var start = DateTimeOffset.UtcNow;
            created(new(1234, 1000, 100, start.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")));
            Check(journal.Entries().Single(e => e.JobId == job.Job.JobId).Phase == "launched", "resume preceded durable observed creation"); Runs++;
            return new(start, DateTimeOffset.UtcNow, 0, true);
        }
    }
}
