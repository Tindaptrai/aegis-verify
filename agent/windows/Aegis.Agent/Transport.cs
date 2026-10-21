using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
namespace Aegis.Agent;

public sealed class Transport : IDisposable
{
    static readonly TimeSpan RequestDeadline = TimeSpan.FromSeconds(20);
    readonly HttpClient client;
    readonly TimeSpan deadline;
    public static Uri ValidateOrigin(string origin)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) ||
            uri.Scheme != "https" || uri.UserInfo != "" || uri.AbsolutePath != "/" ||
            uri.Query != "" || uri.Fragment != "")
            throw new AgentException("AEGIS_HTTPS_ORIGIN_REQUIRED");
        return uri;
    }

    public Transport(string origin, string fingerprint)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            CheckCertificateRevocationList = true,
            ClientCertificateOptions = ClientCertificateOption.Manual
        };
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var certs = store.Certificates.Cast<X509Certificate2>()
            .Where(c => Protocol.Hash(c.RawData) == fingerprint && c.HasPrivateKey)
            .ToArray();
        if (certs.Length != 1)
            throw new AgentException("AEGIS_CLIENT_CERTIFICATE_UNAVAILABLE");
        handler.ClientCertificates.Add(certs[0]);
        client = new HttpClient(handler) { BaseAddress = ValidateOrigin(origin), Timeout = RequestDeadline };
        deadline = RequestDeadline;
    }

    internal Transport(HttpClient client, TimeSpan deadline)
    {
        this.client = client;
        this.deadline = deadline;
    }

    public async Task<byte[]?> Post(string path, string json, bool empty = false)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        using var cancellation = new CancellationTokenSource(deadline);
        using var response = await client.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
        if (empty && response.StatusCode == HttpStatusCode.NoContent)
            return null;
        if (response.StatusCode != HttpStatusCode.OK ||
            response.Content.Headers.ContentType?.MediaType != "application/json")
            throw new AgentException("AEGIS_MANAGER_RESPONSE_REJECTED");

        await using var stream = await response.Content.ReadAsStreamAsync(cancellation.Token);
        using var memory = new MemoryStream();
        var buffer = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(buffer, cancellation.Token)) > 0)
        {
            if (memory.Length + count > 65536)
                throw new AgentException();
            memory.Write(buffer, 0, count);
        }
        return memory.ToArray();
    }

    public async Task Ack(string path, string json, string property)
    {
        var bytes = await Post(path, json);
        using var document = StrictJson.Parse(bytes!);
        StrictJson.Exact(document.RootElement, property);
        if (document.RootElement.GetProperty(property).ValueKind != JsonValueKind.True)
            throw new AgentException();
    }
    public void Dispose() => client.Dispose();
}
