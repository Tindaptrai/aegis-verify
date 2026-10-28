namespace Aegis.Connection;

public static class HeartbeatLoop
{
    public static async Task<int> RunAsync(string stateDirectory, CancellationToken cancellationToken)
    {
        try
        {
            using var store = StateStore.Acquire(stateDirectory);
            var state = store.Read() ?? throw new ConnectionException("identity_missing");
            if (state.Kind != "enrolled") throw new ConnectionException("enrollment_pending");
            if (Expired(state, DateTimeOffset.UtcNow)) { store.MarkFailure("identity_expired"); return 3; }
            using var transport = new AgentClient(state);
            return await RunAsync(store, transport, Task.Delay, () => DateTimeOffset.UtcNow, Random.Shared.NextDouble, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return 0; }
        catch (ConnectionException e) { Console.Error.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { error = new { code = e.Code } })); return 3; }
    }
    internal static async Task<int> RunAsync(StateStore store, IHeartbeatTransport transport, Func<TimeSpan, CancellationToken, Task> wait, Func<DateTimeOffset> utcNow, Func<double> jitter, CancellationToken cancellationToken)
    {
        var retry = 2d;
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var state = store.Read() ?? throw new ConnectionException("identity_missing");
                if (state.Kind != "enrolled") throw new ConnectionException("enrollment_pending");
                if (Expired(state, utcNow())) { store.MarkFailure("identity_expired"); return 3; }
                TimeSpan delay;
                try
                {
                    await transport.HeartbeatAsync(cancellationToken);
                    store.Acknowledge(utcNow()); retry = 2;
                    delay = TimeSpan.FromSeconds(15);
                }
                catch (ConnectionException e) when (e.Transient)
                {
                    delay = TimeSpan.FromSeconds(Math.Min(60, retry * (1 + Math.Clamp(jitter(), 0, 1) * 0.2)));
                    retry = Math.Min(60, retry * 2);
                }
                catch (ConnectionException e) when (e.Code is "identity_denied" or "response_invalid")
                {
                    store.MarkFailure(e.Code); return 3;
                }
                await wait(delay, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return 0; }
    }
    private static bool Expired(IdentityState state, DateTimeOffset now) => !Protocol.Timestamp(state.ExpiresAt ?? "", out var expires) || now >= expires;
}
