using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Aegis.Connection.Execution;

public static class ExecutionProtocol
{
    public const string Version = "aegis-windows-execution/2";
    public const string KeyId = "manager-execution-v2";
    public const string ProviderId = "reviewed-scn001-windows/1";
    public const int RequestLimit = 65536;
    public const int EnvelopeLimit = 98304;
    private static readonly HashSet<string> LocalCodes = ["profile_mismatch", "artifact_mismatch", "clock_uncertain", "local_not_ready", "unsupported_platform"];
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectNullableAnnotations = true, RespectRequiredConstructorParameters = true,
        MaxDepth = 12
    };
    public static byte[] CanonicalBytes<T>(T value)
    {
        using var document = JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(value, Json));
        var output = new StringBuilder();
        void WriteString(string text)
        {
            output.Append('"');
            foreach (var c in text)
            {
                output.Append(c switch
                {
                    '"' => "\\\"", '\\' => "\\\\", '\b' => "\\b", '\f' => "\\f", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t",
                    < ' ' or > '~' => "\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture),
                    _ => c.ToString()
                });
            }
            output.Append('"');
        }
        void Write(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    output.Append('{'); bool first = true;
                    foreach (var property in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                    { if (!first) output.Append(','); first = false; WriteString(property.Name); output.Append(':'); Write(property.Value); }
                    output.Append('}'); break;
                case JsonValueKind.Array:
                    output.Append('['); bool firstItem = true;
                    foreach (var item in element.EnumerateArray()) { if (!firstItem) output.Append(','); firstItem = false; Write(item); }
                    output.Append(']'); break;
                case JsonValueKind.String: WriteString(element.GetString()!); break;
                default: output.Append(element.GetRawText()); break;
            }
        }
        Write(document.RootElement);
        return Encoding.UTF8.GetBytes(output.ToString());
    }
    public static T Decode<T>(byte[] raw, int limit = RequestLimit)
    {
        try
        {
            if (raw.Length == 0 || raw.Length > limit) throw new JsonException();
            using var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 12 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException();
            ValidateJson(document.RootElement);
            var value = JsonSerializer.Deserialize<T>(raw, Json) ?? throw new JsonException();
            ValidateValue(value);
            return value;
        }
        catch (Exception e) when (e is JsonException or NotSupportedException or ArgumentException or InvalidOperationException or FormatException)
        { throw new ConnectionException("execution_invalid"); }
    }
    private static void ValidateJson(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            HashSet<string> names = new(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new JsonException();
                ValidateField(property.Name, property.Value);
                ValidateJson(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var child in value.EnumerateArray()) ValidateJson(child);
    }
    private static string Text(JsonElement value) => value.ValueKind == JsonValueKind.String ? value.GetString()! : throw new JsonException();
    private static void ValidateField(string name, JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Null) return; // Required nullable annotations enforce which fields permit null.
        if (name.EndsWith("_sha256", StringComparison.Ordinal) || name is "baseline" or "behavioral") Digest(Text(value));
        if (name is "device_id" or "binding_id" or "job_id" or "run_id" or "approval_id" or "start_request_id" or "receipt_id") Uuid(Text(value));
        if (name is "generation" or "binding_revision") { if (!value.TryGetInt32(out var n) || n < 1) throw new JsonException(); }
        if (name == "release_id") { if (!value.TryGetInt64(out var n) || n < 1) throw new JsonException(); }
        if (name is "not_before" or "expires_at" or "collection_start" or "collection_end" or "server_time" or "started_at" or "finished_at") Instant(Text(value));
        if (name == "protocol" && Text(value) != Version || name == "key_id" && Text(value) != KeyId ||
            name == "provider_id" && Text(value) != ProviderId || name == "scenario_id" && Text(value) != "SCN-001" ||
            name == "runner_id" && Text(value) != "scn001-safe-demo" || name == "runner_version" && Text(value) != "0.3.0") throw new JsonException();
        if (name == "schema_version" && (!value.TryGetInt32(out var version) || version != 1)) throw new JsonException();
        if (name == "environment_id" && !Regex.IsMatch(Text(value), "\\A[A-Za-z0-9_-]{1,64}\\z")) throw new JsonException();
        if (name == "timeout_seconds" && (!value.TryGetInt32(out var timeout) || timeout is < 180 or > 300)) throw new JsonException();
        if (name is "accepted" or "authorized" && value.ValueKind != JsonValueKind.True) throw new JsonException();
        if (name is "payload" or "signature") Base64(Text(value));
    }
    private static void ValidateValue<T>(T value)
    {
        switch (value)
        {
            case SignedJob job:
                if (job.RunId != job.JobId) throw new JsonException();
                Parameters(job.Parameters);
                var start = Instant(job.NotBefore); var end = Instant(job.ExpiresAt);
                var cstart = Instant(job.CollectionStart); var cend = Instant(job.CollectionEnd);
                if (!(cstart <= start && start < end && end.AddSeconds(job.TimeoutSeconds) <= cend) ||
                    (end - start).TotalSeconds > 120 || (cend - cstart).TotalSeconds > 900) throw new JsonException();
                break;
            case ReadinessRequest readiness:
                Codes(readiness.Ready, readiness.BlockingCodes);
                break;
            case ExecutionReceipt receipt:
                if (receipt.State is not ("succeeded" or "failed" or "execution_unknown") ||
                    receipt.StartedAt != null && Instant(receipt.StartedAt) > Instant(receipt.FinishedAt) ||
                    receipt.State == "succeeded" && (receipt.StartedAt == null || receipt.ExitCode != 0 || !receipt.CleanupSucceeded) ||
                    receipt.State == "failed" && receipt.StartedAt == null) throw new JsonException();
                break;
        }
    }
    private static void Codes(bool ready, IReadOnlyList<string> codes)
    {
        if (codes.Count > 8 || codes.Distinct(StringComparer.Ordinal).Count() != codes.Count ||
            codes.Any(code => !LocalCodes.Contains(code)) || ready && codes.Count != 0) throw new JsonException();
    }
    private static void Parameters(ExecutionParameters value)
    {
        if (value.RunLabel is not ("A" or "B" or "C" or "Rehearsal") || value.RuleRevision is not ("baseline" or "behavioral") ||
            value.RunLabel is "A" or "B" && value.RuleRevision != "baseline" || value.RunLabel == "C" && value.RuleRevision != "behavioral") throw new JsonException();
    }
    private static void Uuid(string value)
    { if (!Guid.TryParseExact(value, "D", out var id) || id == Guid.Empty || id.ToString() != value) throw new JsonException(); }
    private static void Digest(string value)
    { if (!Regex.IsMatch(value, "\\A[0-9a-f]{64}\\z", RegexOptions.CultureInvariant)) throw new JsonException(); }
    private static DateTimeOffset Instant(string value)
    {
        if (!DateTimeOffset.TryParseExact(value, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var result)) throw new JsonException();
        return result;
    }
    private static byte[] Base64(string value)
    { var result = Convert.FromBase64String(value); if (result.Length == 0 || Convert.ToBase64String(result) != value) throw new JsonException(); return result; }
    private static byte[] Serialize<T>(T value)
    { var raw = JsonSerializer.SerializeToUtf8Bytes(value, Json); Decode<T>(raw); return raw; }
    public static byte[] SerializeReadiness(ReadinessRequest value) => Serialize(value);
    public static byte[] SerializePoll(PollRequest value) => Serialize(value);
    public static byte[] SerializeStart(StartRequest value) => Serialize(value);
    public static byte[] SerializeReceipt(ExecutionReceipt value) => Serialize(value);
    public static ReadinessAcknowledgment ReadinessAck(byte[] raw) => Decode<ReadinessAcknowledgment>(raw);
    public static StartAcknowledgment StartAck(byte[] raw) => Decode<StartAcknowledgment>(raw);
    public static ReceiptAcknowledgment ReceiptAck(byte[] raw) => Decode<ReceiptAcknowledgment>(raw);
    public static VerifiedExecutionJob Verify(byte[] envelope, RSA key, ExecutionGrant grant, DateTimeOffset now)
    {
        try
        {
            // Copy before verification: caller mutation cannot alter a validated result.
            envelope = (byte[])envelope.Clone();
            var wire = Decode<ExecutionEnvelope>(envelope, EnvelopeLimit);
            var payload = Base64(wire.Payload); var signature = Base64(wire.Signature);
            if (payload.Length > RequestLimit || key.KeySize != 3072 ||
                Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())) != grant.PublicKeySha256 ||
                !key.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) throw new JsonException();
            var job = Decode<SignedJob>(payload);
            // In-memory grants must still satisfy all closed local contract rules.
            var installed = Decode<InstalledGrant>(JsonSerializer.SerializeToUtf8Bytes(grant.Installed, Json));
            var profile = Decode<InstallationProfile>(JsonSerializer.SerializeToUtf8Bytes(grant.Profile, Json));
            if (Convert.ToHexStringLower(SHA256.HashData(CanonicalBytes(profile))) != installed.InstallationProfileSha256 ||
                Convert.ToHexStringLower(SHA256.HashData(CanonicalBytes(new { profile.ArtifactPins, profile.RulePins }))) != installed.ArtifactSetSha256)
                throw new JsonException();
            var identity = grant.Identity;
            if (identity.Kind != "enrolled" || identity.Os != "windows" || identity.Architecture != "x64" || identity.CertificatePem == null) throw new JsonException();
            using var certificate = X509Certificate2.CreateFromPem(identity.CertificatePem);
            var fingerprint = Convert.ToHexStringLower(SHA256.HashData(certificate.RawData));
            if (job.DeviceId != identity.DeviceId || job.Generation != identity.Generation || job.EnvironmentId != identity.EnvironmentId ||
                profile.EnvironmentId != identity.EnvironmentId || installed.DeviceId != identity.DeviceId || installed.Generation != identity.Generation ||
                installed.CertificateSha256 != fingerprint || job.CertificateSha256 != fingerprint ||
                job.BindingId != installed.BindingId || job.BindingRevision != installed.BindingRevision ||
                job.TimeoutSeconds != profile.TimeoutSeconds || now < Instant(job.NotBefore) || now >= Instant(job.ExpiresAt) ||
                now < certificate.NotBefore.ToUniversalTime() || now >= certificate.NotAfter.ToUniversalTime()) throw new JsonException();
            var pins = profile.ArtifactPins;
            if (job.ScenarioSha256 != pins.ScenarioSha256 || job.ProfileSha256 != pins.ProfileSha256 || job.RunnerSha256 != pins.RunnerSha256 ||
                job.KitSha256 != pins.KitSha256 || job.PayloadSha256 != pins.PayloadSha256 ||
                job.Parameters.RunLabel == "Rehearsal" && !profile.AllowRehearsal ||
                job.Parameters.RuleSha256 != (job.Parameters.RuleRevision == "baseline" ? profile.RulePins.Baseline : profile.RulePins.Behavioral)) throw new JsonException();
            return new VerifiedExecutionJob(envelope, payload, Convert.ToHexStringLower(SHA256.HashData(payload)), job);
        }
        catch (Exception e) when (e is JsonException or CryptographicException or ArgumentException or FormatException or InvalidOperationException)
        { throw new ConnectionException("execution_invalid"); }
    }
}
