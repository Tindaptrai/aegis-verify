using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Aegis.Connection.Execution;

internal static partial class Program
{
    private static int ExecutionVector(string directory)
    {
        try
        {
            // Test harness only: all material is generated into a temporary directory.
            // This calls the production verifier with an ephemeral PUBLIC key, never bypassing it.
            var profile = ExecutionProtocol.Decode<InstallationProfile>(File.ReadAllBytes(Path.Combine(directory, "profile.json")));
            var installed = ExecutionProtocol.Decode<InstalledGrant>(File.ReadAllBytes(Path.Combine(directory, "installed.json")));
            var certificate = File.ReadAllText(Path.Combine(directory, "certificate.pem"));
            using var key = RSA.Create(); key.ImportFromPem(File.ReadAllText(Path.Combine(directory, "public.pem")));
            var identity = new Aegis.Connection.IdentityState("enrolled", "https://synthetic.invalid", "unused", "unused", "unused",
                profile.ExpectedComputerName, "windows", "x64", "0.2.0", installed.DeviceId, profile.EnvironmentId,
                installed.Generation, certificate);
            var grant = new ExecutionGrant(profile, installed, identity, Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())));
            var raw = File.ReadAllBytes(Path.Combine(directory, "envelope.json"));
            var job = ExecutionProtocol.Verify(raw, key, grant, DateTimeOffset.UtcNow);
            Check(job.EnvelopeBytes.SequenceEqual(raw), "raw envelope lost");
            var bytes = job.EnvelopeBytes; bytes[0] ^= 1;
            Check(job.EnvelopeBytes.SequenceEqual(raw), "verified bytes mutable");
            Check(job.JobSha256 != job.Job.PayloadSha256, "script/job digest conflated");
            Console.WriteLine(job.JobSha256);
            return 0;
        }
        catch (Aegis.Connection.ConnectionException) { Console.Error.WriteLine("execution_invalid"); return 2; }
    }
    private static void ExecutionProtocolTests()
    {
        Test("execution protocol signing key is exactly RSA3072", () =>
        {
            var (original, grant) = ExecutionFixture();
            foreach (var size in new[] { 2048, 3072, 4096 })
            {
                using var key = RSA.Create(size);
                var configured = grant with { PublicKeySha256 = ExecutionProfile.Hash(key.ExportSubjectPublicKeyInfo()) };
                var payload = original.PayloadBytes;
                var envelope = ExecutionProtocol.CanonicalBytes(new ExecutionEnvelope(ExecutionProtocol.Version, ExecutionProtocol.KeyId,
                    Convert.ToBase64String(payload), Convert.ToBase64String(key.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))));
                if (size == 3072) Check(ExecutionProtocol.Verify(envelope, key, configured, DateTimeOffset.UtcNow).PayloadBytes.SequenceEqual(payload), "RSA3072 rejected or bytes changed");
                else Denied(() => ExecutionProtocol.Verify(envelope, key, configured, DateTimeOffset.UtcNow), "execution_invalid");
            }
        });
        Test("execution protocol strict vectors", () =>
        {
            var accepted = Encoding.UTF8.GetBytes("{\"protocol\":\"aegis-windows-execution/2\",\"server_time\":\"2026-10-25T12:00:00Z\",\"accepted\":true}");
            Check(ExecutionProtocol.ReadinessAck(accepted).Accepted, "ack rejected");
            foreach (var text in new[] { Encoding.UTF8.GetString(accepted).Replace("true", "false"),
                Encoding.UTF8.GetString(accepted).Replace("/2", "/1"),
                Encoding.UTF8.GetString(accepted).Replace("\"accepted\":", "\"accepted\":true,\"accepted\":"),
                Encoding.UTF8.GetString(accepted).Replace("12:00:00Z", "12:00:00.1Z"),
                Encoding.UTF8.GetString(accepted).Replace("\"protocol\":", "\"extra\":0,\"protocol\":"),
                new string(' ', 65537), "[]" })
                Denied(() => ExecutionProtocol.ReadinessAck(Encoding.UTF8.GetBytes(text)));
        });
        Test("execution protocol required nullable fields and immutable blocking codes", () =>
        {
            var text = """
                {"protocol":"aegis-windows-execution/2","device_id":"a1111111-1111-4111-8111-111111111111","generation":1,"binding_id":"a1111111-1111-4111-8111-111111111111","binding_revision":1,"installation_profile_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifact_set_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ready":false,"blocking_codes":["clock_uncertain"]}
                """;
            var readiness = ExecutionProtocol.Decode<ReadinessRequest>(Encoding.UTF8.GetBytes(text));
            try { ((IList<string>)readiness.BlockingCodes)[0] = "local_not_ready"; throw new Exception("blocking codes were mutable"); }
            catch (NotSupportedException) { }
            foreach (var property in JsonNode.Parse(text)!.AsObject().ToArray())
            {
                var node = JsonNode.Parse(text)!.AsObject(); node.Remove(property.Key);
                Denied(() => ExecutionProtocol.Decode<ReadinessRequest>(Encoding.UTF8.GetBytes(node.ToJsonString())));
            }
            foreach (var bad in new[] { text.Replace("false", "true"), text.Replace("clock_uncertain", "binding_disabled"),
                text.Replace("[\"clock_uncertain\"]", "[\"clock_uncertain\",\"clock_uncertain\"]"), text.Replace("\"generation\":1", "\"generation\":true"),
                text.Replace("\"generation\":1", "\"generation\":2147483648"), text.Replace("a1111111-", "A1111111-"),
                text.Replace("\"binding_revision\":1", "\"binding_revision\":1.0") })
                Denied(() => ExecutionProtocol.Decode<ReadinessRequest>(Encoding.UTF8.GetBytes(bad)));
        });
        Test("execution protocol request size and receipt semantics", () =>
        {
            var poll = Encoding.UTF8.GetBytes("{\"protocol\":\"aegis-windows-execution/2\",\"device_id\":\"a1111111-1111-4111-8111-111111111111\",\"generation\":1,\"binding_id\":\"a1111111-1111-4111-8111-111111111111\",\"binding_revision\":1}");
            var boundary = poll.Concat(Enumerable.Repeat((byte)' ', 65536 - poll.Length)).ToArray();
            ExecutionProtocol.Decode<PollRequest>(boundary);
            Denied(() => ExecutionProtocol.Decode<PollRequest>(boundary.Concat(new byte[] { 32 }).ToArray()));
            var receipt = """
                {"protocol":"aegis-windows-execution/2","device_id":"a1111111-1111-4111-8111-111111111111","generation":1,"binding_id":"a1111111-1111-4111-8111-111111111111","binding_revision":1,"receipt_id":"a1111111-1111-4111-8111-111111111111","job_id":"a1111111-1111-4111-8111-111111111111","job_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"succeeded","started_at":"2026-10-25T12:00:00Z","finished_at":"2026-10-25T12:01:00Z","exit_code":0,"cleanup_succeeded":true}
                """;
            ExecutionProtocol.Decode<ExecutionReceipt>(Encoding.UTF8.GetBytes(receipt));
            foreach (var bad in new[] { receipt.Replace("\"exit_code\":0", "\"exit_code\":true"), receipt.Replace("\"cleanup_succeeded\":true", "\"cleanup_succeeded\":false"),
                receipt.Replace("12:01:00Z", "11:59:59Z"), receipt.Replace("\"started_at\":\"2026-10-25T12:00:00Z\"", "\"started_at\":null"),
                receipt.Replace("succeeded", "detected") }) Denied(() => ExecutionProtocol.Decode<ExecutionReceipt>(Encoding.UTF8.GetBytes(bad)));
            var unknown = receipt.Replace("\"state\":\"succeeded\"", "\"state\":\"execution_unknown\"").Replace("\"started_at\":\"2026-10-25T12:00:00Z\"", "\"started_at\":null").Replace("\"exit_code\":0", "\"exit_code\":null");
            Check(ExecutionProtocol.Decode<ExecutionReceipt>(Encoding.UTF8.GetBytes(unknown)).StartedAt == null, "unknown invented a start");
        });
    }
}
