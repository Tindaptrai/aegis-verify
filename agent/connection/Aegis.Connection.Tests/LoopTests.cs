using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Aegis.Connection;

internal static partial class Program
{
    private sealed class Heartbeats(Func<CancellationToken, Task<HeartbeatResponse>> send) : IHeartbeatTransport
    {
        public Task<HeartbeatResponse> HeartbeatAsync(CancellationToken cancellationToken) => send(cancellationToken);
    }
    private static void Enroll(StateStore store, Issuer issuer)
    {
        var pending = store.Prepare("https://manager.invalid", issuer.Certificate.ExportCertificatePem()); store.Promote(issuer.Issue(pending));
    }
    private static partial void LoopTests()
    {
        Test("loop immediate success persists local acknowledgement then waits fifteen seconds", async () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); using var store = StateStore.Acquire(temp.Path); Enroll(store, issuer);
            using var cancel = new CancellationTokenSource(); var events = new List<string>(); var time = DateTimeOffset.UtcNow;
            var transport = new Heartbeats(_ => { events.Add("request"); return Task.FromResult(new HeartbeatResponse("2.0", "2026-10-24T00:00:00Z", 15, 60)); });
            var exit = await HeartbeatLoop.RunAsync(store, transport, (delay, _) => { events.Add("wait:" + delay.TotalSeconds); Check(store.Read()!.LastAcknowledgedAt == time.ToString("O"), "local acknowledgement not saved before wait"); cancel.Cancel(); return Task.FromCanceled(cancel.Token); }, () => time, () => 0, cancel.Token);
            Check(exit == 0 && events.SequenceEqual(new[] { "request", "wait:15" }), "heartbeat was not immediate or cadence incorrect");
        });
        Test("loop transient backoff caps sixty and recovery resets delay same identity", async () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); using var store = StateStore.Acquire(temp.Path); Enroll(store, issuer);
            var original = store.Read()!; using var cancel = new CancellationTokenSource(); var waits = new List<double>(); int requests = 0;
            var transport = new Heartbeats(_ =>
            {
                requests++; if (requests <= 7 || requests == 9) throw new ConnectionException("network_unavailable", transient: true);
                return Task.FromResult(new HeartbeatResponse("2.0", "2026-10-24T00:00:00Z", 15, 60));
            });
            var exit = await HeartbeatLoop.RunAsync(store, transport, (delay, _) => { waits.Add(delay.TotalSeconds); if (waits.Count == 9) { cancel.Cancel(); return Task.FromCanceled(cancel.Token); } return Task.CompletedTask; }, () => DateTimeOffset.UtcNow, () => 0, cancel.Token);
            Check(exit == 0 && waits.SequenceEqual(new double[] { 2, 4, 8, 16, 32, 60, 60, 15, 2 }), "backoff/cap/reset incorrect");
            Check(store.Read()!.PrivateKeyPem == original.PrivateKeyPem && store.Read()!.DeviceId == original.DeviceId && store.Read()!.LastAcknowledgedAt != null, "recovery changed identity");
        });
        Test("loop bounded jitter authorization terminal failure and request cancellation", async () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); using var store = StateStore.Acquire(temp.Path); Enroll(store, issuer);
            int attempts = 0; var waits = new List<double>();
            var transport = new Heartbeats(_ => { if (++attempts == 1) throw new ConnectionException("network_unavailable", true); throw new ConnectionException("identity_denied"); });
            var exit = await HeartbeatLoop.RunAsync(store, transport, (delay, _) => { waits.Add(delay.TotalSeconds); return Task.CompletedTask; }, () => DateTimeOffset.UtcNow, () => 1, CancellationToken.None);
            Check(exit == 3 && attempts == 2 && waits.SequenceEqual(new[] { 2.4 }) && store.Read()!.Failure == "identity_denied", "terminal identity or jitter incorrect");
            using var cancel = new CancellationTokenSource();
            var waiting = new Heartbeats(async token => { cancel.Cancel(); await Task.Delay(Timeout.InfiniteTimeSpan, token); throw new Exception("unreachable"); });
            Check(await HeartbeatLoop.RunAsync(store, waiting, (_, _) => throw new Exception("unexpected delay"), () => DateTimeOffset.UtcNow, () => 0, cancel.Token) == 0, "pending request cancellation nonzero");
        });
        Test("loop expired certificate stops before network and pending refuses run", async () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); using var store = StateStore.Acquire(temp.Path); Enroll(store, issuer);
            var transport = new Heartbeats(_ => throw new Exception("expired identity sent request"));
            Check(await HeartbeatLoop.RunAsync(store, transport, (_, _) => throw new Exception("unexpected delay"), () => DateTimeOffset.UtcNow.AddDays(31), () => 0, CancellationToken.None) == 3 && store.Read()!.Failure == "identity_expired", "expiry did not stop loop");
            using var pendingPath = new Scratch(); using (var pending = StateStore.Acquire(pendingPath.Path)) pending.Prepare("https://manager.invalid", issuer.Certificate.ExportCertificatePem());
            var stderr = Console.Error; using var error = new StringWriter();
            try { Console.SetError(error); Check(await HeartbeatLoop.RunAsync(pendingPath.Path, CancellationToken.None) == 3 && error.ToString().Contains("enrollment_pending"), "pending state ran"); }
            finally { Console.SetError(stderr); }
        });
        Test("loop real TLS interruption recovers with same mTLS identity and no code", async () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); using var tlsCa = new Issuer(); using var store = StateStore.Acquire(temp.Path); int requests = 0;
            await using var endpoint = new TlsEndpoint(tlsCa, (_, body) => { Check(!body.Contains("pairing_code"), "code retried on heartbeat"); return ++requests switch { 1 => new Reply(503, "{\"error\":{\"code\":\"temporarily_unavailable\"}}"), 2 => new Reply(200, HeartbeatOk), _ => new Reply(403, "{\"error\":{\"code\":\"identity_denied\"}}") }; }, clientIssuer: issuer.Certificate);
            var pending = store.Prepare(endpoint.Origin, tlsCa.Certificate.ExportCertificatePem()); store.Promote(issuer.Issue(pending));
            using var client = new AgentClient(store.Read()!); var waits = new List<double>();
            var exit = await HeartbeatLoop.RunAsync(store, client, (delay, _) => { waits.Add(delay.TotalSeconds); return Task.CompletedTask; }, () => DateTimeOffset.UtcNow, () => 0, CancellationToken.None);
            Check(exit == 3 && requests == 3 && waits.SequenceEqual(new[] { 2d, 15d }) && endpoint.ClientFingerprints.Distinct().Count() == 1 && endpoint.ClientFingerprints.Count == 3 && store.Read()!.LastAcknowledgedAt != null, "real TLS recovery failed");
        });
    }
}
