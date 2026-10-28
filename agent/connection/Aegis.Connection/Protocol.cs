using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Aegis.Connection;

public sealed record EnrollmentResponse(string Protocol, string DeviceId, string EnvironmentId, int Generation,
    string CertificatePem, string IssuerPem, string ExpiresAt, int HeartbeatSeconds, int OfflineAfterSeconds);
public sealed record HeartbeatResponse(string Protocol, string ServerTime, int HeartbeatSeconds, int OfflineAfterSeconds);

public static class Protocol
{
    public static string AgentVersion { get; } = typeof(Protocol).Assembly.GetName().Version!.ToString(3);
    internal const int ResponseLimit = 16384;
    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        MaxDepth = 8
    };
    public static byte[] EnrollmentRequest(IdentityState state, string code)
    {
        if (!Regex.IsMatch(code, "\\A[0-9a-f]{64}\\z", RegexOptions.CultureInvariant)) throw new ConnectionException("pairing_code_invalid");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { protocol = "2.0", pairing_code = code, csr_pem = state.CsrPem, hostname = state.Hostname, os = state.Os, architecture = state.Architecture, agent_version = AgentVersion });
        if (bytes.Length > ResponseLimit) throw new ConnectionException("configuration_invalid");
        return bytes;
    }
    public static byte[] HeartbeatRequest(IdentityState state) => JsonSerializer.SerializeToUtf8Bytes(new { protocol = "2.0", device_id = state.DeviceId, generation = state.Generation });
    internal static byte[] NetworkHeartbeatRequest(IdentityState state, NetworkSnapshot network)
    {
        if (network.AgentVersion != AgentVersion) throw new ConnectionException("configuration_invalid");
        if (network.CollectionStatus == "unavailable")
        {
            if (network.ReportedIps != null || network.Truncated) throw new ConnectionException("configuration_invalid");
        }
        else if (network.CollectionStatus == "ok" && network.ReportedIps is { Length: <= 32 } ips)
        {
            var addresses = new List<IPAddress>();
            foreach (var text in ips)
            {
                if (text == null || !IPAddress.TryParse(text, out var address)) throw new ConnectionException("configuration_invalid");
                addresses.Add(address);
            }
            var normalized = NetworkInventory.Normalize([new(true, addresses)]);
            if (!ips.SequenceEqual(normalized.ReportedIps!) || network.Truncated && ips.Length != 32) throw new ConnectionException("configuration_invalid");
        }
        else throw new ConnectionException("configuration_invalid");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { protocol = "2.1", device_id = state.DeviceId, generation = state.Generation, network }, Json);
        if (bytes.Length > ResponseLimit) throw new ConnectionException("configuration_invalid");
        return bytes;
    }
    public static EnrollmentResponse Enrollment(byte[] json)
    {
        var value = Decode<EnrollmentResponse>(json, ResponseLimit, "response_invalid");
        ValidateEnrollmentFields(value, "response_invalid");
        return value;
    }
    internal static void ValidateEnrollmentFields(EnrollmentResponse value, string error)
    {
        if (value.Protocol != "2.0" || !Uuid(value.DeviceId) || !Environment(value.EnvironmentId) || value.Generation != 1 || value.HeartbeatSeconds != 15 || value.OfflineAfterSeconds != 60 || !Timestamp(value.ExpiresAt, out _) || value.CertificatePem.Length > 8192 || value.IssuerPem.Length > 8192)
            throw new ConnectionException(error);
    }
    public static HeartbeatResponse Heartbeat(byte[] json) => Heartbeat(json, "2.0");
    internal static HeartbeatResponse NetworkHeartbeat(byte[] json) => Heartbeat(json, "2.1");
    private static HeartbeatResponse Heartbeat(byte[] json, string protocol)
    {
        var value = Decode<HeartbeatResponse>(json, ResponseLimit, "response_invalid");
        if (value.Protocol != protocol || value.HeartbeatSeconds != 15 || value.OfflineAfterSeconds != 60 || !Timestamp(value.ServerTime, out _)) throw new ConnectionException("response_invalid");
        return value;
    }
    public static Uri Origin(string origin)
    {
        // Check the supplied spelling before Uri normalizes dot segments or empty paths.
        if (string.IsNullOrEmpty(origin) || origin != origin.Trim() || origin.Contains('\\') || !origin.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) throw new ConnectionException("configuration_invalid");
        var authority = origin[8..];
        if (authority.Length == 0 || authority.IndexOfAny(['/', '?', '#', '@']) >= 0 || !Uri.TryCreate(origin, UriKind.Absolute, out var result) || result.Scheme != "https" || result.Host.Length == 0 || result.Port is < 1 or > 65535 || result.HostNameType is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6)) throw new ConnectionException("configuration_invalid");
        return result;
    }
    internal static bool Uuid(string value) => Guid.TryParseExact(value, "D", out var uuid) && uuid != Guid.Empty && uuid.ToString() == value;
    internal static bool Environment(string value) => Regex.IsMatch(value, "\\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\\z", RegexOptions.CultureInvariant);
    internal static bool Timestamp(string value, out DateTimeOffset result) => DateTimeOffset.TryParseExact(value, ["yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out result);
    internal static T Decode<T>(byte[] bytes, int limit, string error)
    {
        try
        {
            if (bytes.Length == 0 || bytes.Length > limit) throw new JsonException();
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
            Unique(document.RootElement);
            return JsonSerializer.Deserialize<T>(bytes, Json) ?? throw new JsonException();
        }
        catch (Exception e) when (e is JsonException or NotSupportedException or ArgumentException) { throw new ConnectionException(error); }
    }
    private static void Unique(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new JsonException();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!names.Add(property.Name)) throw new JsonException();
            if (property.Value.ValueKind == JsonValueKind.Object) Unique(property.Value);
            if (property.Value.ValueKind == JsonValueKind.Array) throw new JsonException();
        }
    }
}
