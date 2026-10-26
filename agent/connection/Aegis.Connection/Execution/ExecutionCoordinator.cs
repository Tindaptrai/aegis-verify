using System.Globalization;

namespace Aegis.Connection.Execution;

public interface IExecutionTransport
{
    Task<byte[]> ReadinessAsync(ReadinessRequest request, CancellationToken stop);
    Task<VerifiedExecutionJob?> PollAsync(PollRequest request, CancellationToken stop);
    Task<byte[]> StartAsync(string jobId, StartRequest request, byte[] exactBytes, CancellationToken stop);
    Task<byte[]> ReceiptAsync(ExecutionReceipt request, byte[] exactBytes, CancellationToken stop);
}
public interface IExecutionRunner
{
    Task<ExecutionObservation> RunAsync(VerifiedExecutionJob job, ExecutionGrant grant, CancellationToken stop);
}
internal interface IExecutionLifecycleRunner
{
    void ConfigureLifecycle(Func<CancellationToken, Task> beforeCreate, Action<ExecutionCreation> observedCreated);
}

public sealed class ExecutionCoordinator
{
    private readonly Func<VerifiedExecutionJob?, CancellationToken, Task<bool>> readiness;
    private readonly Func<TimeSpan, CancellationToken, Task> delay;
    internal ExecutionCoordinator(Func<VerifiedExecutionJob?, CancellationToken, Task<bool>> readiness,
        Func<TimeSpan, CancellationToken, Task>? delay = null)
    { this.readiness = readiness; this.delay = delay ?? Task.Delay; }

    public async Task RunAsync(IdentityState identity, ExecutionGrant grant, IExecutionTransport transport,
        ExecutionJournal journal, IExecutionRunner runner, CancellationToken stop)
    {
        await RecoverAsync(journal, transport, stop);
        var retry = 1;
        while (!stop.IsCancellationRequested)
        {
            try
            {
                // Manager fences owner reconciliation. A new signed lease/start ack
                // can authorize a distinct job; old IDs remain permanent tombstones.
                if (!journal.Entries().Any(Unresolved) && journal.HasAdmissionCapacity() && await readiness(null, stop))
                {
                    var poll = new PollRequest(ExecutionProtocol.Version, identity.DeviceId!, identity.Generation!.Value,
                        grant.Installed.BindingId, grant.Installed.BindingRevision);
                    var job = await transport.PollAsync(poll, stop);
                    if (job != null) await AttemptAsync(job, grant, transport, journal, runner, stop);
                }
                retry = 1;
                await delay(TimeSpan.FromSeconds(5), stop);
            }
            catch (ConnectionException e) when (e.Transient)
            { await delay(TimeSpan.FromSeconds(retry), stop); retry = Math.Min(30, retry * 2); }
        }
    }
    internal static bool Unresolved(ExecutionJournalEntry entry) => entry.Phase != "accepted";

    internal async Task AttemptAsync(VerifiedExecutionJob job, ExecutionGrant grant, IExecutionTransport transport,
        ExecutionJournal journal, IExecutionRunner runner, CancellationToken stop)
    {
        var prior = journal.Entries();
        if (prior.Any(e => e.JobId == job.Job.JobId)) return;
        if (prior.Any(Unresolved)) throw new ConnectionException("execution_reconciliation_required");
        var entry = ExecutionJournalEntry.Received(job);
        journal.Transition(entry.JobId, null, entry);
        void Save(ExecutionJournalEntry next)
        { journal.Transition(entry.JobId, entry.Phase, next); entry = next; }
        try
        {
            if (!await readiness(job, stop)) throw new ConnectionException("execution_not_ready");
            var request = new StartRequest(ExecutionProtocol.Version, job.Job.DeviceId, job.Job.Generation,
                job.Job.BindingId, job.Job.BindingRevision, Guid.NewGuid().ToString(), job.JobSha256);
            var exact = ExecutionProtocol.SerializeStart(request);
            Save(entry with { Phase = "start_requested", StartRequest = Convert.ToBase64String(exact) });
            byte[] ack; var backoff = 1;
            while (true)
            {
                stop.ThrowIfCancellationRequested();
                if (DateTimeOffset.UtcNow >= Instant(job.Job.ExpiresAt) || !await readiness(job, stop)) throw new ConnectionException("execution_not_ready");
                try { ack = await transport.StartAsync(job.Job.JobId, request, (byte[])exact.Clone(), stop); break; }
                catch (ConnectionException e) when (e.Transient)
                { await delay(TimeSpan.FromSeconds(backoff), stop); backoff = Math.Min(30, backoff * 2); }
            }
            // Validate exact ack binding before persisting authorization.
            var authorized = ExecutionProtocol.StartAck(ack);
            if (authorized.JobId != job.Job.JobId || authorized.JobSha256 != job.JobSha256 || authorized.StartRequestId != request.StartRequestId)
                throw new ConnectionException("execution_invalid");
            Save(entry with { Phase = "authorized", StartAck = Convert.ToBase64String(ack) });
            Save(entry with { Phase = "launch_intent" });
            if (runner is not IExecutionLifecycleRunner lifecycle) throw new ConnectionException("execution_invalid");
            lifecycle.ConfigureLifecycle(async token =>
            {
                token.ThrowIfCancellationRequested();
                if (!await readiness(job, token)) throw new ConnectionException("execution_not_ready");
            }, observed => Save(entry with { Phase = "launched", Creation = observed }));
            var result = await runner.RunAsync(job, grant, stop);
            var observedStart = entry.Creation == null ? null : result.StartedAt;
            var state = observedStart == null || !result.CleanupSucceeded || result.ExitCode == null ? "execution_unknown" : result.ExitCode == 0 ? "succeeded" : "failed";
            var receipt = Receipt(entry, state, observedStart, result.FinishedAt, result.ExitCode, result.CleanupSucceeded);
            Save(entry with { Phase = "terminal", Receipt = Convert.ToBase64String(receipt) });
        }
        catch (Exception error) when (error is ConnectionException or IOException or UnauthorizedAccessException or OperationCanceledException)
        {
            // Re-read disk after ambiguous publication failure; never try native creation again.
            entry = journal.Entries().Single(e => e.JobId == job.Job.JobId);
            if (entry.Phase is not ("terminal" or "accepted")) Save(entry with { Phase = "terminal", Receipt = Convert.ToBase64String(Unknown(entry, DateTimeOffset.UtcNow)) });
            if (error is ConnectionException { Code: "identity_denied" }) throw;
        }
        if (!stop.IsCancellationRequested) await DeliverAsync(entry, journal, transport, stop);
    }
    internal async Task RecoverAsync(ExecutionJournal journal, IExecutionTransport transport, CancellationToken stop)
    {
        foreach (var original in journal.Entries())
        {
            if (original.Phase == "accepted") continue;
            var entry = original;
            if (entry.Phase != "terminal")
            {
                entry = entry with { Phase = "terminal", Receipt = Convert.ToBase64String(Unknown(entry, DateTimeOffset.UtcNow)) };
                journal.Transition(entry.JobId, original.Phase, entry);
            }
            await DeliverAsync(entry, journal, transport, stop);
        }
    }
    private async Task DeliverAsync(ExecutionJournalEntry entry, ExecutionJournal journal, IExecutionTransport transport, CancellationToken stop)
    {
        var bytes = ExecutionJournal.Raw(entry.Receipt!); var receipt = ExecutionProtocol.Decode<ExecutionReceipt>(bytes); var retry = 1;
        while (true)
        {
            stop.ThrowIfCancellationRequested();
            try
            {
                var exact = await transport.ReceiptAsync(receipt, (byte[])bytes.Clone(), stop);
                var ack = ExecutionProtocol.ReceiptAck(exact);
                if (ack.JobId != entry.JobId || ack.JobSha256 != entry.JobSha256 || ack.ReceiptId != receipt.ReceiptId) throw new ConnectionException("execution_invalid");
                journal.Transition(entry.JobId, "terminal", entry with { Phase = "accepted", ReceiptAck = Convert.ToBase64String(exact) });
                return;
            }
            catch (ConnectionException e) when (e.Transient)
            { await delay(TimeSpan.FromSeconds(retry), stop); retry = Math.Min(30, retry * 2); }
        }
    }
    internal static byte[] Unknown(ExecutionJournalEntry entry, DateTimeOffset finish) => Receipt(entry, "execution_unknown",
        entry.Creation == null ? null : Instant(entry.Creation.ObservedAt), finish, null, false);
    private static byte[] Receipt(ExecutionJournalEntry entry, string state, DateTimeOffset? start, DateTimeOffset finish, int? exit, bool cleanup)
    {
        if (start > finish) start = null;
        var job = entry.Job;
        return ExecutionProtocol.SerializeReceipt(new(ExecutionProtocol.Version, job.DeviceId, job.Generation, job.BindingId, job.BindingRevision,
            Guid.NewGuid().ToString(), entry.JobId, entry.JobSha256, state, start.HasValue ? Stamp(start.Value) : null, Stamp(finish), exit, cleanup));
    }
    internal static string Stamp(DateTimeOffset time) => time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    internal static DateTimeOffset Instant(string time) => DateTimeOffset.ParseExact(time, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
}
