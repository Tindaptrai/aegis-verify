using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Aegis.Connection;

internal static partial class Program
{
    private sealed record Reply(int Status, string Body, string? ExtraHeader = null, int DelayMilliseconds = 0);
    private sealed class TlsEndpoint : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new();
        private readonly X509Certificate2 server;
        private readonly Task loop;
        private readonly Func<string, string, Reply> reply;
        private readonly X509Certificate2? clientIssuer;
        public string Origin { get; }
        public List<string> ClientFingerprints { get; } = [];
        public List<(string Path, string Body)> Requests { get; } = [];
        public TlsEndpoint(Issuer issuer, Func<string, string, Reply> reply, string name = "ip", X509Certificate2? clientIssuer = null)
        {
            this.reply = reply; this.clientIssuer = clientIssuer;
            using var key = RSA.Create(3072);
            var req = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
            if (name != "cn") { var san = new SubjectAlternativeNameBuilder(); if (name == "ip" || name == "expired") san.AddIpAddress(IPAddress.Loopback); else san.AddDnsName(name); req.CertificateExtensions.Add(san.Build()); }
            var notBefore = DateTimeOffset.UtcNow.AddHours(-3); var notAfter = name == "expired" ? DateTimeOffset.UtcNow.AddHours(-1) : DateTimeOffset.UtcNow.AddDays(1);
            using var leaf = req.Create(issuer.Certificate, notBefore, notAfter, RandomNumberGenerator.GetBytes(16));
            using var withKey = leaf.CopyWithPrivateKey(key);
            server = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx), null, OperatingSystem.IsWindows() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet);
            listener.Start(); Origin = "https://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port;
            loop = Serve();
        }
        private async Task Serve()
        {
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    using var socket = await listener.AcceptTcpClientAsync(stop.Token);
                    using var tls = new SslStream(socket.GetStream(), false, (_, cert, _, _) =>
                    {
                        if (clientIssuer == null) return true;
                        if (cert == null) return false;
                        using var remote = new X509Certificate2(cert); using var chain = new X509Chain();
                        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust; chain.ChainPolicy.CustomTrustStore.Add(clientIssuer); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        var valid = chain.Build(remote);
                        if (valid) ClientFingerprints.Add(remote.GetCertHashString(HashAlgorithmName.SHA256));
                        return valid;
                    });
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = server, ClientCertificateRequired = clientIssuer != null, EnabledSslProtocols = SslProtocols.Tls12, CertificateRevocationCheckMode = X509RevocationMode.NoCheck }, stop.Token);
                    var bytes = new List<byte>(); var one = new byte[1];
                    while (bytes.Count < 16384)
                    {
                        if (await tls.ReadAsync(one, stop.Token) == 0) break; bytes.Add(one[0]);
                        if (bytes.Count >= 4 && bytes.TakeLast(4).SequenceEqual(new byte[] { 13, 10, 13, 10 })) break;
                    }
                    var header = Encoding.ASCII.GetString(bytes.ToArray()); if (header.Length == 0) continue;
                    var path = header.Split(' ')[1];
                    var lengthLine = header.Split("\r\n").Single(h => h.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
                    var length = int.Parse(lengthLine.Split(':')[1].Trim()); if (length > 16384) throw new Exception("client request too large");
                    var body = new byte[length]; await tls.ReadExactlyAsync(body, stop.Token);
                    var text = Encoding.UTF8.GetString(body); Requests.Add((path, text));
                    var response = reply(path, text); var payload = Encoding.UTF8.GetBytes(response.Body);
                    if (response.DelayMilliseconds > 0) await Task.Delay(response.DelayMilliseconds, stop.Token);
                    var result = $"HTTP/1.1 {response.Status} Synthetic\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n{response.ExtraHeader}\r\n";
                    await tls.WriteAsync(Encoding.ASCII.GetBytes(result), stop.Token); await tls.WriteAsync(payload, stop.Token); await tls.FlushAsync(stop.Token);
                }
                catch (Exception e) when (e is IOException or AuthenticationException or OperationCanceledException or SocketException) { }
                catch (ObjectDisposedException) when (stop.IsCancellationRequested) { break; }
            }
        }
        public async ValueTask DisposeAsync() { stop.Cancel(); listener.Stop(); await loop; stop.Dispose(); server.Dispose(); }
    }
    private static async Task RejectedAsync(Func<Task> action, string? code = null)
    {
        try { await action(); } catch (ConnectionException e) when (code == null || e.Code == code) { return; }
        throw new Exception("Expected rejection " + code);
    }
    private const string HeartbeatOk = "{\"protocol\":\"2.0\",\"server_time\":\"2026-10-24T01:02:03Z\",\"heartbeat_seconds\":15,\"offline_after_seconds\":60}";
    private static partial void TransportTests()
    {
        Test("TLS real IP SAN enrollment then actual client certificate heartbeat", async () =>
        {
            using var temp = new Scratch(); using var ca = new Issuer(); using var identityCa = new Issuer(); using var store = StateStore.Acquire(temp.Path);
            IdentityState? pending = null;
            await using (var endpoint = new TlsEndpoint(ca, (path, body) =>
            {
                Check(path == "/agent/v2/enroll", "wrong enrollment route");
                Check(store.Read()!.Kind == "pending", "request sent before durable pending write");
                using var doc = JsonDocument.Parse(body); Check(doc.RootElement.GetProperty("pairing_code").GetString() == new string('a', 64) && doc.RootElement.GetProperty("agent_version").GetString() == "0.3.0" && doc.RootElement.GetProperty("protocol").GetString() == "2.0", "code/version/protocol wire mismatch");
                return new Reply(201, JsonSerializer.Serialize(identityCa.Issue(pending!), Protocol.Json));
            }))
            {
                pending = store.Prepare(endpoint.Origin, ca.Certificate.ExportCertificatePem());
                using var client = new AgentClient(pending); store.Promote(await client.EnrollAsync(new string('a', 64), CancellationToken.None));
                Check(endpoint.Requests.Count == 1, "enrollment retried");
            }
            var enrolled = store.Read()!;
            await using var heartbeat = new TlsEndpoint(ca, (path, body) =>
            {
                Check(path == "/agent/v2/network-heartbeat", "wrong heartbeat route");
                Check(!body.Contains("pairing_code") && !body.Contains("PRIVATE"), "heartbeat leaked enrollment secret");
                return new Reply(200, NetworkOk);
            }, clientIssuer: identityCa.Certificate);
            using var connection = new AgentClient(enrolled with { ManagerOrigin = heartbeat.Origin });
            Check((await connection.HeartbeatAsync(CancellationToken.None)).HeartbeatSeconds == 15, "heartbeat response invalid");
            Check(heartbeat.ClientFingerprints.Count == 1 && heartbeat.ClientFingerprints[0] == X509Certificate2.CreateFromPem(enrolled.CertificatePem!).GetCertHashString(HashAlgorithmName.SHA256), "actual mTLS identity missing");
        });
        Test("TLS wrong name IP-as-DNS CN fallback expired and wrong CA rejected", async () =>
        {
            using var ca = new Issuer(); using var other = new Issuer();
            foreach (var name in new[] { "wrong.invalid", "127.0.0.1", "cn", "expired", "ip" })
            {
                await using var endpoint = new TlsEndpoint(ca, (_, _) => new Reply(200, HeartbeatOk), name);
                using var client = new AgentClient(new IdentityState("pending", endpoint.Origin, (name == "ip" ? other : ca).Certificate.ExportCertificatePem(), "", "csr", "synthetic", "linux", "x64", "0.1.0"));
                await RejectedAsync(async () => await client.EnrollAsync(new string('a', 64), CancellationToken.None), "network_unavailable");
                Check(endpoint.Requests.Count == 0, "untrusted request disclosed pairing code");
            }
        });
        Test("TLS redirect oversized duplicate unknown denied transient closed responses", async () =>
        {
            using var ca = new Issuer();
            foreach (var item in new[] { (new Reply(302, "{}", "Location: https://redirect.invalid/\r\n"), "response_invalid"), (new Reply(200, new string(' ', 16385)), "response_invalid"), (new Reply(200, HeartbeatOk.Replace("\"protocol\":", "\"extra\":1,\"protocol\":")), "response_invalid"), (new Reply(200, HeartbeatOk.Replace("\"protocol\":", "\"protocol\":\"2.0\",\"protocol\":")), "response_invalid"), (new Reply(403, "{\"error\":{\"code\":\"identity_denied\"}}"), "identity_denied"), (new Reply(503, "{\"error\":{\"code\":\"temporarily_unavailable\"}}"), "temporarily_unavailable"), (new Reply(429, ""), "temporarily_unavailable") })
            {
                await using var endpoint = new TlsEndpoint(ca, (_, _) => item.Item1);
                using var client = new AgentClient(new IdentityState("pending", endpoint.Origin, ca.Certificate.ExportCertificatePem(), "", "csr", "synthetic", "linux", "x64", "0.1.0"));
                await RejectedAsync(async () => await client.HeartbeatAsync(CancellationToken.None), item.Item2);
                Check(endpoint.Requests.Count == 1, "HTTP redirected or internally retried");
            }
        });
        Test("TLS lost enrollment response retains pending key for replacement code", async () =>
        {
            using var temp = new Scratch(); using var ca = new Issuer(); using var store = StateStore.Acquire(temp.Path);
            using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
            var state = store.Prepare("https://127.0.0.1:" + port, ca.Certificate.ExportCertificatePem());
            using var client = new AgentClient(state); await RejectedAsync(async () => await client.EnrollAsync(new string('a', 64), CancellationToken.None), "network_unavailable");
            Check(store.Prepare(state.ManagerOrigin, state.ServerCaPem).PrivateKeyPem == state.PrivateKeyPem, "failed enrollment regenerated key");
        });
        Test("TLS proxy malformed503 is transient bounded and never enrollment success", async () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); using var store = StateStore.Acquire(temp.Path);
            await using var endpoint = new TlsEndpoint(issuer, (_, _) => new Reply(503, "<html>synthetic proxy outage</html>"));
            var state = store.Prepare(endpoint.Origin, issuer.Certificate.ExportCertificatePem()); using var client = new AgentClient(state);
            try { await client.EnrollAsync(new string('a', 64), CancellationToken.None); throw new Exception("503 enrolled identity"); }
            catch (ConnectionException e) { Check(e.Transient && e.Code == "temporarily_unavailable" && store.Read()!.Kind == "pending" && endpoint.Requests.Count == 1, "503 classification/state incorrect"); }
        });
        Test("TLS ten second deadline and caller cancellation interrupt pending response", async () =>
        {
            using var issuer = new Issuer();
            await using (var endpoint = new TlsEndpoint(issuer, (_, _) => new Reply(200, HeartbeatOk, DelayMilliseconds: 12000)))
            {
                using var client = new AgentClient(new IdentityState("pending", endpoint.Origin, issuer.Certificate.ExportCertificatePem(), "", "csr", "synthetic", "linux", "x64", "0.1.0"));
                var elapsed = System.Diagnostics.Stopwatch.StartNew();
                await RejectedAsync(async () => await client.HeartbeatAsync(CancellationToken.None), "network_unavailable");
                Check(elapsed.Elapsed.TotalSeconds is >= 8 and < 12, "request deadline was not ten seconds");
            }
            await using (var endpoint = new TlsEndpoint(issuer, (_, _) => new Reply(200, HeartbeatOk, DelayMilliseconds: 12000)))
            {
                using var client = new AgentClient(new IdentityState("pending", endpoint.Origin, issuer.Certificate.ExportCertificatePem(), "", "csr", "synthetic", "linux", "x64", "0.1.0"));
                using var cancel = new CancellationTokenSource(250); var elapsed = System.Diagnostics.Stopwatch.StartNew();
                try { await client.HeartbeatAsync(cancel.Token); throw new Exception("cancelled response accepted"); }
                catch (OperationCanceledException) when (cancel.IsCancellationRequested) { }
                Check(elapsed.Elapsed.TotalSeconds < 2, "request cancellation did not interrupt");
            }
        });
    }
}
