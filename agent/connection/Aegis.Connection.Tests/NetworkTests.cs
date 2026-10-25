using System.Net;
using System.Text.Json;
using Aegis.Connection;

internal static partial class Program
{
    private sealed class CollectionClock : TimeProvider
    {
        private long ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => ticks;
        public void Advance(TimeSpan duration) => ticks += duration.Ticks;
    }
    private static IReadOnlyList<InterfaceAddresses> Interfaces(params string[] ips) => [new(true, ips.Select(IPAddress.Parse).ToArray())];
    private static NetworkInventory Inventory(Func<Task<IReadOnlyList<InterfaceAddresses>>> source) => new(source, (_, token) => Task.Delay(Timeout.InfiniteTimeSpan, token), new CollectionClock());
    private static void Snapshot(NetworkSnapshot value, string status, string[]? ips, bool truncated = false) =>
        Check(value.CollectionStatus == status && (ips == null ? value.ReportedIps == null : value.ReportedIps != null && value.ReportedIps.SequenceEqual(ips)) && value.Truncated == truncated && value.AgentVersion == "0.2.0", "incorrect collection snapshot: " + JsonSerializer.Serialize(value));
    private const string NetworkOk = "{\"protocol\":\"2.1\",\"server_time\":\"2026-10-24T01:02:03Z\",\"heartbeat_seconds\":15,\"offline_after_seconds\":60}";
    private static void NetworkTests()
    {
        Test("network TLS 0.1 and0.2 enrolled state preserved across DHCP unavailable and archived denial", async () =>
        {
            foreach (var version in new[] { "0.1.0", "0.2.0" })
            {
                using var temp = new Scratch(); using var ca = new Issuer(); using var identityCa = new Issuer(); int received = 0;
                await using var endpoint = new TlsEndpoint(ca, (_, body) =>
                {
                    using var doc = JsonDocument.Parse(body); var network = doc.RootElement.GetProperty("network");
                    Check(network.EnumerateObject().Count() == 4 && network.GetProperty("agent_version").GetString() == "0.2.0", "network DTO/version incorrect");
                    if (++received <= 2) Check(network.GetProperty("reported_ips")[0].GetString() == (received == 1 ? "192.0.2.10" : "192.0.2.20"), "DHCP snapshot not refreshed");
                    else Check(network.GetProperty("reported_ips").ValueKind == JsonValueKind.Null && network.GetProperty("collection_status").GetString() == "unavailable", "failed sample kept stale IP");
                    return received == 4 ? new Reply(403,"{\"error\":{\"code\":\"identity_denied\"}}") : new Reply(200,NetworkOk);
                }, clientIssuer: identityCa.Certificate);
                IdentityState original;
                using (var store = StateStore.Acquire(temp.Path)) { var pending = store.Prepare(endpoint.Origin, ca.Certificate.ExportCertificatePem()); store.Promote(identityCa.Issue(pending)); original = store.Read()! with { AgentVersion = version }; }
                var path = Path.Combine(temp.Path,"state.json"); File.WriteAllBytes(path,JsonSerializer.SerializeToUtf8Bytes(original,Protocol.Json)); var before = File.ReadAllBytes(path);
                using var active = StateStore.Acquire(temp.Path); var restored = active.Read()!; int samples = 0;
                var collector = Inventory(() => ++samples <= 2 ? Task.FromResult(Interfaces(samples == 1 ? "192.0.2.10" : "192.0.2.20")) : Task.FromException<IReadOnlyList<InterfaceAddresses>>(new System.Net.NetworkInformation.NetworkInformationException()));
                using var client = new AgentClient(restored,new NetworkHeartbeat(collector));
                await client.HeartbeatAsync(CancellationToken.None); await client.HeartbeatAsync(CancellationToken.None); await client.HeartbeatAsync(CancellationToken.None);
                Check(File.ReadAllBytes(path).SequenceEqual(before) && active.Read() == original, "network reporting rewrote identity/version");
                await RejectedAsync(async () => await client.HeartbeatAsync(CancellationToken.None),"identity_denied");
                Check(endpoint.Requests.Count == 4 && endpoint.Requests.All(r => r.Path == "/agent/v2/network-heartbeat") && endpoint.ClientFingerprints.Count == 4, "archive denial retried/downgraded or lost mTLS");
                Check(File.ReadAllBytes(path).SequenceEqual(before), "denied request mutated protected identity");
            }
        });
        Test("network actual CLI process restart reprobes missing route retaining old enrolled identity", async () =>
        {
            using var temp = new Scratch(); using var ca = new Issuer(); using var identityCa = new Issuer();
            await using var endpoint = new TlsEndpoint(ca,(path,_) => path == "/agent/v2/network-heartbeat" ? new Reply(404,new string('x',20000)) : new Reply(403,"{\"error\":{\"code\":\"identity_denied\"}}"),clientIssuer:identityCa.Certificate);
            IdentityState original;
            using(var store = StateStore.Acquire(temp.Path)) { var pending=store.Prepare(endpoint.Origin,ca.Certificate.ExportCertificatePem()); store.Promote(identityCa.Issue(pending)); original=store.Read()! with { AgentVersion="0.1.0" }; }
            File.WriteAllBytes(Path.Combine(temp.Path,"state.json"),JsonSerializer.SerializeToUtf8Bytes(original,Protocol.Json));
            for(var run=0;run<2;run++)
            {
                var start=new System.Diagnostics.ProcessStartInfo("dotnet") { UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true,WindowStyle=System.Diagnostics.ProcessWindowStyle.Hidden };
                foreach(var arg in new[] { typeof(Aegis.Connection.Program).Assembly.Location,"run","--state-dir",temp.Path }) start.ArgumentList.Add(arg);
                using var child=System.Diagnostics.Process.Start(start) ?? throw new Exception("CLI failed to start");
                var output=child.StandardOutput.ReadToEndAsync(); var error=child.StandardError.ReadToEndAsync();
                using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(25));
                try { await child.WaitForExitAsync(deadline.Token); } catch { child.Kill(entireProcessTree:true); throw; }
                var diagnostic=await error; Check(child.ExitCode==3 && diagnostic.Split("network_reporting_unsupported").Length==2 && !(await output).Contains("PRIVATE"),"CLI fallback/error incorrect");
                using var state=StateStore.Acquire(temp.Path); Check(state.Read()==original with { Failure="identity_denied" },"restart replaced enrolled identity/version");
            }
            Check(endpoint.Requests.Select(r=>r.Path).SequenceEqual(new[] { "/agent/v2/network-heartbeat","/agent/v2/heartbeat","/agent/v2/network-heartbeat","/agent/v2/heartbeat" }),"real process restart did not reset fallback");
        });
        Test("network enrollment retries preserved old pending key with running version and never falls back", async () =>
        {
            using var ca = new Issuer();
            await using var endpoint = new TlsEndpoint(ca, (_, _) => new Reply(404, "missing route"));
            var state = new IdentityState("pending", endpoint.Origin, ca.Certificate.ExportCertificatePem(), "", "csr", "synthetic", "linux", "x64", "0.1.0");
            using var client = new AgentClient(state, new NetworkHeartbeat());
            await RejectedAsync(async () => await client.EnrollAsync(new string('a', 64), CancellationToken.None), "response_invalid");
            Check(endpoint.Requests.Count == 1 && endpoint.Requests.Single().Path == "/agent/v2/enroll", "enrollment fallback/retry");
            using var body = JsonDocument.Parse(endpoint.Requests.Single().Body);
            Check(body.RootElement.GetProperty("agent_version").GetString() == "0.2.0", "old pending snapshot hid new binary enrollment version");
        });
        Test("network payload rejects inconsistent unbounded or noncanonical snapshots while legacy arrays stay rejected", () =>
        {
            var state = new IdentityState("pending", "https://manager.invalid", "ca", "", "csr", "synthetic", "linux", "x64", "0.1.0");
            foreach (var invalid in new[] {
                new NetworkSnapshot("unavailable", [], false, "0.2.0"), new("unavailable", null, true, "0.2.0"), new("ok", null, false, "0.2.0"), new("unknown", null, false, "0.2.0"), new("ok", [], true, "0.2.0"), new("ok", ["127.0.0.1"], false, "0.2.0"), new("ok", ["2001:db8::1%4"], false, "0.2.0"), new("ok", ["::ffff:192.0.2.1"], false, "0.2.0"), new("ok", ["192.0.2.2", "192.0.2.1"], false, "0.2.0"), new("ok", ["192.0.2.1", "192.0.2.1"], false, "0.2.0"), new("ok", [], false, "0.1.0"), new("ok", Enumerable.Range(1,33).Select(n => "192.0.2." + n).ToArray(), false, "0.2.0") })
                Denied(() => Protocol.NetworkHeartbeatRequest(state, invalid), "configuration_invalid");
            foreach (var invalid in new[] { "[]", "{\"protocol\":[]}", "{\"error\":{\"code\":[]}}" })
                Denied(() => Protocol.Decode<HeartbeatResponse>(System.Text.Encoding.UTF8.GetBytes(invalid),16384,"response_invalid"), "response_invalid");
        });
        Test("network TLS all non404 statuses malformed2.1 and wrong TLS trust never downgrade", async () =>
        {
            using var ca = new Issuer();
            var cases = new[] { (400, "{\"error\":{\"code\":\"invalid_request\"}}", "response_invalid"), (401,"{}","response_invalid"), (403,"{\"error\":{\"code\":\"identity_denied\"}}","identity_denied"), (429,"","temporarily_unavailable"), (500,"", "temporarily_unavailable"), (503,"", "temporarily_unavailable"), (200,HeartbeatOk,"response_invalid"), (200,NetworkOk.Replace("15","16"),"response_invalid"), (200,NetworkOk.Replace("\"protocol\":", "\"unknown\":[],\"protocol\":"),"response_invalid"), (200,NetworkOk.Replace("\"protocol\":", "\"protocol\":\"2.1\",\"protocol\":"),"response_invalid") };
            foreach (var (status, body, code) in cases)
            {
                int requests = 0;
                await using var endpoint = new TlsEndpoint(ca, (_, _) => ++requests == 1 ? new Reply(status, body) : new Reply(200, NetworkOk));
                using var client = new AgentClient(new IdentityState("pending", endpoint.Origin, ca.Certificate.ExportCertificatePem(), "", "csr", "synthetic", "linux", "x64", "0.1.0"), new NetworkHeartbeat());
                await RejectedAsync(async () => await client.HeartbeatAsync(CancellationToken.None), code);
                await client.HeartbeatAsync(CancellationToken.None);
                Check(endpoint.Requests.Count == 2 && endpoint.Requests.All(r => r.Path == "/agent/v2/network-heartbeat"), "non404 activated fallback");
            }
            await using var untrusted = new TlsEndpoint(ca, (_, _) => new Reply(404,""), "wrong.invalid");
            var capability = new NetworkHeartbeat();
            using var badTls = new AgentClient(new IdentityState("pending",untrusted.Origin,ca.Certificate.ExportCertificatePem(),"","csr","synthetic","linux","x64","0.1.0"), capability);
            await RejectedAsync(async () => await badTls.HeartbeatAsync(CancellationToken.None), "network_unavailable");
            Check(!capability.Unsupported && untrusted.Requests.Count == 0, "TLS failure downgraded or disclosed request");
        });
        Test("network collector filters inactive excluded scoped addresses and sorts mapped deduplicated bytes", async () =>
        {
            var input = Interfaces("2001:db8::10", "192.0.2.10", "10.0.0.2", "::ffff:192.0.2.10", "2001:db8::2", "127.1.2.3", "::1", "0.0.0.0", "::", "224.0.0.1", "239.255.255.255", "ff02::1", "169.254.1.1", "fe80::1", "2001:db8::3%4").Concat([new InterfaceAddresses(false, [IPAddress.Parse("10.0.0.1")])]).ToArray();
            var collector = Inventory(() => Task.FromResult<IReadOnlyList<InterfaceAddresses>>(input));
            Snapshot(await collector.CollectAsync(CancellationToken.None), "ok", ["10.0.0.2", "192.0.2.10", "2001:db8::2", "2001:db8::10"]);
        });
        Test("network collector sorts before 32 cap and marks truncation only for additional unique eligible IP", async () =>
        {
            var many = Enumerable.Range(1, 33).Reverse().Select(n => "192.0.2." + n).Concat(["::ffff:192.0.2.1", "127.0.0.1"]).ToArray();
            var collector = Inventory(() => Task.FromResult(Interfaces(many)));
            var expected = Enumerable.Range(1, 32).Select(n => "192.0.2." + n).ToArray();
            Snapshot(await collector.CollectAsync(CancellationToken.None), "ok", expected, true);
            collector = Inventory(() => Task.FromResult(Interfaces(expected.Concat(["::ffff:192.0.2.1"]).ToArray())));
            Snapshot(await collector.CollectAsync(CancellationToken.None), "ok", expected);
        });
        Test("network collector successful empty differs from failed native enumeration", async () =>
        {
            Snapshot(await Inventory(() => Task.FromResult(Interfaces("127.0.0.1", "fe80::1"))).CollectAsync(CancellationToken.None), "ok", []);
            Snapshot(await Inventory(() => Task.FromException<IReadOnlyList<InterfaceAddresses>>(new System.Net.NetworkInformation.NetworkInformationException())).CollectAsync(CancellationToken.None), "unavailable", null);
        });
        Test("network collector stuck native task single flight deadline late discard then fresh DHCP sample", async () =>
        {
            // Inline continuation makes SetResult a deterministic completion barrier
            // for the collector's normalization, without a scheduler-dependent sleep.
            var read = new TaskCompletionSource<IReadOnlyList<InterfaceAddresses>>();
            var elapsed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var clock = new CollectionClock(); int starts = 0;
            var collector = new NetworkInventory(() => ++starts == 1 ? read.Task : Task.FromResult(Interfaces("192.0.2.20")), (duration, _) => { Check(duration == TimeSpan.FromSeconds(2), "wrong deadline"); return elapsed.Task; }, clock);
            var first = collector.CollectAsync(CancellationToken.None);
            Snapshot(await collector.CollectAsync(CancellationToken.None), "unavailable", null);
            Check(starts == 1 && !first.IsCompleted, "overlapping read or no deadline wait");
            clock.Advance(TimeSpan.FromSeconds(2)); elapsed.SetResult();
            Snapshot(await first, "unavailable", null);
            Snapshot(await collector.CollectAsync(CancellationToken.None), "unavailable", null);
            Check(starts == 1, "started another OS read while first stuck");
            read.SetResult(Interfaces("192.0.2.10"));
            // A fresh pending deadline, never a wall-clock sleep. The abandoned sample
            // is complete, but only a new OS read may contribute a new heartbeat.
            elapsed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            Snapshot(await collector.CollectAsync(CancellationToken.None), "ok", ["192.0.2.20"]);
            Check(starts == 2, "late data reused instead of DHCP refresh");
        });
        Test("network collector completed read at deadline is discarded even before timer continuation", async () =>
        {
            var clock = new CollectionClock();
            var collector = new NetworkInventory(() => { clock.Advance(TimeSpan.FromSeconds(2)); return Task.FromResult(Interfaces("192.0.2.10")); }, (_, token) => Task.Delay(Timeout.InfiniteTimeSpan, token), clock);
            Snapshot(await collector.CollectAsync(CancellationToken.None), "unavailable", null);
        });
        Test("network collector cancellation never releases a stuck native read for overlap", async () =>
        {
            var read = new TaskCompletionSource<IReadOnlyList<InterfaceAddresses>>(TaskCreationOptions.RunContinuationsAsynchronously); int starts = 0;
            var collector = Inventory(() => { starts++; return read.Task; }); using var cancel = new CancellationTokenSource();
            var first = collector.CollectAsync(cancel.Token); cancel.Cancel();
            try { await first; throw new Exception("cancellation ignored"); } catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
            Snapshot(await collector.CollectAsync(CancellationToken.None), "unavailable", null); Check(starts == 1, "cancellation overlapped read");
            read.SetException(new System.Net.NetworkInformation.NetworkInformationException());
        });
        Test("network new enrollment announces binary version with unchanged protocol", () =>
        {
            using var temp = new Scratch(); using var ca = new Issuer(); using var store = StateStore.Acquire(temp.Path);
            var state = store.Prepare("https://manager.invalid", ca.Certificate.ExportCertificatePem());
            using var body = JsonDocument.Parse(Protocol.EnrollmentRequest(state, new string('a', 64)));
            Check(state.AgentVersion == "0.2.0" && body.RootElement.GetProperty("agent_version").GetString() == "0.2.0" && body.RootElement.GetProperty("protocol").GetString() == "2.0", "new enrollment version/protocol incorrect");
        });
        Test("network TLS new heartbeat uses 2.1 and running version", async () =>
        {
            using var ca = new Issuer();
            await using var endpoint = new TlsEndpoint(ca, (_, _) => new Reply(200, NetworkOk));
            using var client = new AgentClient(new IdentityState("pending", endpoint.Origin, ca.Certificate.ExportCertificatePem(), "", "csr", "synthetic", "linux", "x64", "0.1.0"));
            await client.HeartbeatAsync(CancellationToken.None);
            using var body = JsonDocument.Parse(endpoint.Requests.Single().Body);
            Check(endpoint.Requests.Single().Path == "/agent/v2/network-heartbeat" && body.RootElement.GetProperty("protocol").GetString() == "2.1", "new route/protocol absent");
            Check(body.RootElement.GetProperty("network").GetProperty("agent_version").GetString() == "0.2.0", "reported persisted version instead of binary version");
        });
        Test("network TLS 404 arbitrary body falls back once per process and restart probes again", async () =>
        {
            using var ca = new Issuer();
            await using var endpoint = new TlsEndpoint(ca, (path, _) => path == "/agent/v2/network-heartbeat" ? new Reply(404, "<html>missing route</html>") : new Reply(200, HeartbeatOk));
            var state = new IdentityState("pending", endpoint.Origin, ca.Certificate.ExportCertificatePem(), "", "csr", "synthetic", "linux", "x64", "0.1.0");
            var process = new NetworkHeartbeat();
            var oldError = Console.Error; using var error = new StringWriter();
            try
            {
                Console.SetError(error);
                using (var client = new AgentClient(state, process)) { await client.HeartbeatAsync(CancellationToken.None); await client.HeartbeatAsync(CancellationToken.None); }
                Check(endpoint.Requests.Select(r => r.Path).SequenceEqual(new[] { "/agent/v2/network-heartbeat", "/agent/v2/heartbeat", "/agent/v2/heartbeat" }), "fallback route/lifetime incorrect");
                Check(error.ToString().Split("network_reporting_unsupported").Length == 2, "unsupported diagnostic repeated/absent");
                using (var replacement = new AgentClient(state, process)) { await replacement.HeartbeatAsync(CancellationToken.None); }
                Check(endpoint.Requests[3].Path == "/agent/v2/heartbeat", "recreating client reset process capability");
                using var restarted = new AgentClient(state, new NetworkHeartbeat()); await restarted.HeartbeatAsync(CancellationToken.None);
                Check(endpoint.Requests[4].Path == "/agent/v2/network-heartbeat", "restart did not probe new protocol");
            }
            finally { Console.SetError(oldError); }
        });
    }
}
