using System.Net;

namespace Aegis.Connection.Execution;

public sealed class ExecutionClient(AgentClient client, ExecutionGrant grant, string publicKeyPath, ExecutionClock clock) : IExecutionTransport
{
    public async Task<byte[]> ReadinessAsync(ReadinessRequest request, CancellationToken stop) =>
        await client.SendExecutionAsync("/agent/v2/execution/readiness", ExecutionProtocol.SerializeReadiness(request), ExecutionProtocol.RequestLimit, false, stop)
            ?? throw Invalid();
    public async Task<VerifiedExecutionJob?> PollAsync(PollRequest request, CancellationToken stop)
    {
        var raw = await client.SendExecutionAsync("/agent/v2/execution/poll", ExecutionProtocol.SerializePoll(request), ExecutionProtocol.EnvelopeLimit, true, stop);
        if (raw == null) return null;
        if (!clock.TryGetBounds(clock.MonotonicNow, out var bounds)) throw new ConnectionException("clock_uncertain");
        using var key = ExecutionProfile.LoadSigningKey(publicKeyPath, grant);
        var job = ExecutionProtocol.Verify(raw, key, grant, bounds.EarliestUtc);
        if (bounds.LatestUtc >= ExecutionCoordinator.Instant(job.Job.ExpiresAt)) throw new ConnectionException("clock_uncertain");
        return job;
    }
    public async Task<byte[]> StartAsync(string jobId, StartRequest request, byte[] exactBytes, CancellationToken stop)
    {
        if (!Protocol.Uuid(jobId) || ExecutionProtocol.Decode<StartRequest>(exactBytes) != request) throw Invalid();
        return await client.SendExecutionAsync("/agent/v2/execution/jobs/" + jobId + "/start", (byte[])exactBytes.Clone(), ExecutionProtocol.RequestLimit, false, stop) ?? throw Invalid();
    }
    public async Task<byte[]> ReceiptAsync(ExecutionReceipt request, byte[] exactBytes, CancellationToken stop)
    {
        if (ExecutionProtocol.Decode<ExecutionReceipt>(exactBytes) != request) throw Invalid();
        return await client.SendExecutionAsync("/agent/v2/execution/receipt", (byte[])exactBytes.Clone(), ExecutionProtocol.RequestLimit, false, stop) ?? throw Invalid();
    }
    internal static async Task<byte[]?> ReadResponseAsync(HttpResponseMessage response, int limit, bool allowEmpty, CancellationToken stop)
    {
        if (response.Content.Headers.ContentLength > limit || response.Content.Headers.ContentEncoding.Count > 0) throw Invalid();
        using var input = await response.Content.ReadAsStreamAsync(stop); using var output = new MemoryStream();
        var buffer = new byte[4096]; int count;
        while ((count = await input.ReadAsync(buffer, stop)) > 0)
        {
            if (output.Length + count > limit) throw Invalid();
            output.Write(buffer, 0, count);
        }
        var raw = output.ToArray();
        if (response.StatusCode == HttpStatusCode.NoContent)
        { if (!allowEmpty || raw.Length != 0) throw Invalid(); return null; }
        if (response.Content.Headers.ContentType?.MediaType != "application/json") throw Invalid();
        if (response.StatusCode == HttpStatusCode.OK) return raw;
        ErrorEnvelope error;
        try { error = ExecutionProtocol.Decode<ErrorEnvelope>(raw); }
        catch (ConnectionException) { throw Invalid(); }
        var status = (int)response.StatusCode;
        if (status == 403 && error.Error.Code == "identity_denied") throw new ConnectionException("identity_denied");
        if (status == 503 && error.Error.Code == "temporarily_unavailable") throw new ConnectionException("temporarily_unavailable", true);
        if (status == 409 && error.Error.Code is "lease_conflict" or "start_conflict" or "receipt_conflict" || status == 404 && error.Error.Code == "job_not_found")
            throw new ConnectionException(error.Error.Code);
        throw Invalid();
    }
    private sealed record ErrorEnvelope(ErrorCode Error);
    private sealed record ErrorCode(string Code);
    private static ConnectionException Invalid() => new("execution_invalid");
}
