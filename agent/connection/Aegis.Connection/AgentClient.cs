using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Aegis.Connection;

public interface IHeartbeatTransport
{
    Task<HeartbeatResponse> HeartbeatAsync(CancellationToken cancellationToken);
}

public sealed class AgentClient : IHeartbeatTransport, IDisposable
{
    private readonly IdentityState state;
    private readonly HttpClient client;
    private readonly X509Certificate2 serverCa;
    private readonly X509Certificate2? clientCertificate;
    private readonly X509Certificate2? issuer;
    private readonly Uri origin;
    private readonly NetworkHeartbeat network;
    public AgentClient(IdentityState state) : this(state, NetworkHeartbeat.Process) { }
    internal AgentClient(IdentityState state, NetworkHeartbeat network)
    {
        this.network = network;
        this.state = state; origin = Protocol.Origin(state.ManagerOrigin);
        try
        {
            serverCa = Certificates.PublicPem(state.ServerCaPem); Certificates.RequireCa(serverCa);
            var ssl = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, remote, _, _) => ValidateServer(remote)
            };
            if (state.Kind == "enrolled")
            {
                using var pemCertificate = X509Certificate2.CreateFromPem(state.CertificatePem!, state.PrivateKeyPem);
                // Schannel cannot use the ephemeral key returned by CreateFromPem. Import only
                // into an OS temporary user key container, owned by this service identity;
                // no PersistKeySet, certificate store enrollment, or PFX file is used.
                if (OperatingSystem.IsWindows())
                {
                    var pfx = pemCertificate.Export(X509ContentType.Pkcs12);
                    try { clientCertificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet); }
                    finally { CryptographicOperations.ZeroMemory(pfx); }
                }
                else clientCertificate = X509Certificate2.CreateFromPem(state.CertificatePem!, state.PrivateKeyPem);
                issuer = Certificates.PublicPem(state.IssuerPem!);
                ssl.ClientCertificateContext = SslStreamCertificateContext.Create(clientCertificate, new X509Certificate2Collection(issuer), offline: true);
            }
            var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false, UseCookies = false, AutomaticDecompression = DecompressionMethods.None, MaxResponseHeadersLength = 16, ConnectTimeout = TimeSpan.FromSeconds(10), SslOptions = ssl };
            client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException or InvalidOperationException)
        { clientCertificate?.Dispose(); issuer?.Dispose(); serverCa?.Dispose(); throw new ConnectionException("configuration_invalid"); }
    }
    private bool ValidateServer(X509Certificate? remote)
    {
        if (remote == null) return false;
        try
        {
            using var certificate = new X509Certificate2(remote);
            // MatchesHostname distinguishes an exact IP SAN from DNS text and never falls back to CN.
            return certificate.MatchesHostname(origin.IdnHost, allowWildcards: true, allowCommonName: false) && Certificates.Trusted(certificate, serverCa, "1.3.6.1.5.5.7.3.1");
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException) { return false; }
    }
    public async Task<EnrollmentResponse> EnrollAsync(string code, CancellationToken cancellationToken)
    {
        var bytes = await Send("/agent/v2/enroll", Protocol.EnrollmentRequest(state, code), 201, true, cancellationToken);
        return Protocol.Enrollment(bytes);
    }
    public async Task<HeartbeatResponse> HeartbeatAsync(CancellationToken cancellationToken)
    {
        if (!network.Unsupported)
        {
            var snapshot = await network.Inventory.CollectAsync(cancellationToken);
            try
            {
                var networkBytes = await Send("/agent/v2/network-heartbeat", Protocol.NetworkHeartbeatRequest(state, snapshot), 200, false, cancellationToken);
                return Protocol.NetworkHeartbeat(networkBytes);
            }
            catch (NetworkUnsupportedException)
            {
                network.MarkUnsupported();
            }
        }
        var bytes = await Send("/agent/v2/heartbeat", Protocol.HeartbeatRequest(state), 200, false, cancellationToken);
        return Protocol.Heartbeat(bytes);
    }
    private async Task<byte[]> Send(string path, byte[] body, int expectedStatus, bool enrollment, CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(TimeSpan.FromSeconds(10));
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(origin, path));
            request.Content = new ByteArrayContent(body); request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            // Only authenticated HTTP status enables fallback, independently of body.
            if (path == "/agent/v2/network-heartbeat" && response.StatusCode == HttpStatusCode.NotFound) throw new NetworkUnsupportedException();
            if (response.Content.Headers.ContentLength > Protocol.ResponseLimit) throw new ConnectionException("response_invalid");
            using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var output = new MemoryStream(); var buffer = new byte[4096];
            int length;
            while ((length = await stream.ReadAsync(buffer, timeout.Token)) != 0)
            {
                if (output.Length + length > Protocol.ResponseLimit) throw new ConnectionException("response_invalid");
                output.Write(buffer, 0, length);
            }
            var payload = output.ToArray(); var status = (int)response.StatusCode;
            if (status == 429 || status >= 500) throw new ConnectionException("temporarily_unavailable", transient: true);
            if (status != expectedStatus)
            {
                var error = Protocol.Decode<ErrorEnvelope>(payload, Protocol.ResponseLimit, "response_invalid");
                if (status == 403 && error.Error.Code == (enrollment ? "pairing_denied" : "identity_denied")) throw new ConnectionException(error.Error.Code);
                if (status == 400 && error.Error.Code == "invalid_request") throw new ConnectionException("response_invalid");
                throw new ConnectionException("response_invalid");
            }
            if (response.Content.Headers.ContentType?.MediaType != "application/json" || response.Content.Headers.ContentEncoding.Count > 0) throw new ConnectionException("response_invalid");
            return payload;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception e) when (e is HttpRequestException or IOException or OperationCanceledException or AuthenticationException) { throw new ConnectionException("network_unavailable", transient: true, cause: e); }
        finally { CryptographicOperations.ZeroMemory(body); }
    }
    private sealed record ErrorEnvelope(ErrorCode Error);
    internal async Task<byte[]?> SendExecutionAsync(string path, byte[] body, int responseLimit, bool allowEmpty, CancellationToken stop)
    {
        try
        {
            if (!path.StartsWith("/agent/v2/execution/", StringComparison.Ordinal) || body.Length > Execution.ExecutionProtocol.RequestLimit)
                throw new ConnectionException("execution_invalid");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop); timeout.CancelAfter(TimeSpan.FromSeconds(10));
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(origin, path));
            request.Content = new ByteArrayContent(body); request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            return await Execution.ExecutionClient.ReadResponseAsync(response, responseLimit, allowEmpty, timeout.Token);
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { throw; }
        catch (Exception e) when (e is HttpRequestException or IOException or OperationCanceledException or AuthenticationException)
        { throw new ConnectionException("network_unavailable", transient: true); }
        finally { CryptographicOperations.ZeroMemory(body); }
    }
    private sealed class NetworkUnsupportedException : Exception;
    private sealed record ErrorCode(string Code);
    public void Dispose() { client.Dispose(); clientCertificate?.Dispose(); issuer?.Dispose(); serverCa.Dispose(); }
}
