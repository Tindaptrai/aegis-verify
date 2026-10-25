using Aegis.Connection;
using Aegis.Connection.Execution;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

internal static partial class Program
{
    private static void ExecutionClientTests()
    {
        Test("execution transport closes response errors and preserves 204 semantics", async () =>
        {
            using var empty = new HttpResponseMessage(HttpStatusCode.NoContent);
            Check(await ExecutionClient.ReadResponseAsync(empty, 98304, true, CancellationToken.None) == null, "empty poll rejected");
            foreach (var (status, body, code) in new[]
            {
                (403, "{\"error\":{\"code\":\"identity_denied\"}}", "identity_denied"),
                (409, "{\"error\":{\"code\":\"start_conflict\"}}", "start_conflict"),
                (403, "{\"error\":{\"code\":\"identity_denied\",\"extra\":true}}", "execution_invalid"),
                (403, "{\"error\":{\"code\":\"identity_denied\",\"code\":\"identity_denied\"}}", "execution_invalid"),
                (204, "{}", "execution_invalid")
            })
            {
                using var response = new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
                try { await ExecutionClient.ReadResponseAsync(response, 65536, true, CancellationToken.None); throw new Exception("invalid response accepted"); }
                catch (ConnectionException e) { Check(e.Code == code, "wrong error mapping"); }
            }
        });
        Test("execution transport enforces bytes content type encoding and status", async () =>
        {
            foreach (var mode in new[] { "oversize", "encoding", "type", "redirect" })
            {
                using var response = new HttpResponseMessage(mode == "redirect" ? HttpStatusCode.Redirect : HttpStatusCode.OK)
                { Content = new ByteArrayContent(new byte[mode == "oversize" ? 65537 : 1]) };
                response.Content.Headers.ContentType = new MediaTypeHeaderValue(mode == "type" ? "text/plain" : "application/json");
                if (mode == "encoding") response.Content.Headers.ContentEncoding.Add("gzip");
                try { await ExecutionClient.ReadResponseAsync(response, 65536, false, CancellationToken.None); throw new Exception("invalid response accepted"); }
                catch (ConnectionException e) { Check(e.Code == "execution_invalid", "unexpected error"); }
            }
        });
    }
}
