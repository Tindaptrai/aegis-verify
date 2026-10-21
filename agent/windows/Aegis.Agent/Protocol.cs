using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace Aegis.Agent;

public sealed class AgentException : Exception { public AgentException(string code = "AEGIS_INVALID_INPUT") : base(code) { } }
public static class StrictJson
{
    public static JsonDocument Parse(byte[] bytes) { try { if (bytes.Length > 65536) throw new AgentException(); var d = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 12 }); Check(d.RootElement); return d; } catch (JsonException) { throw new AgentException(); } }
    static void Check(JsonElement e) { if (e.ValueKind == JsonValueKind.Object) { var names = new HashSet<string>(StringComparer.Ordinal); foreach (var p in e.EnumerateObject()) { if (!names.Add(p.Name)) throw new AgentException(); Check(p.Value); } } else if (e.ValueKind == JsonValueKind.Array) foreach (var v in e.EnumerateArray()) Check(v); }
    public static void Exact(JsonElement e, params string[] names) { if (e.ValueKind != JsonValueKind.Object || !e.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(names.Order())) throw new AgentException(); }
    public static string S(JsonElement e, string n) { if (!e.TryGetProperty(n, out var p) || p.ValueKind != JsonValueKind.String) throw new AgentException(); return p.GetString()!; }
    public static int I(JsonElement e, string n) { if (!e.TryGetProperty(n, out var p) || !p.TryGetInt32(out var i)) throw new AgentException(); return i; }
}
public sealed record VerifiedJob(string Id, string Digest, byte[] Payload, DateTimeOffset NotBefore, DateTimeOffset Expires, DateTimeOffset CollectionEnd, int Timeout, string Label, string Revision, string RuleHash);
public static class Protocol
{
    public static string Time(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    public static DateTimeOffset Date(JsonElement e, string n) { var s = StrictJson.S(e, n); if (!DateTimeOffset.TryParseExact(s, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t)) throw new AgentException(); return t; }
    public static string Hash(byte[] b) => Convert.ToHexStringLower(SHA256.HashData(b));
    static byte[] Base64(string s) { try { var b = Convert.FromBase64String(s); if (Convert.ToBase64String(b) != s) throw new AgentException(); return b; } catch (FormatException) { throw new AgentException(); } }
    public static VerifiedJob Verify(byte[] envelope, RSA key, string agent, string environment, int generation, IReadOnlyDictionary<string, string> pins, IReadOnlyDictionary<string, string> rules, bool rehearsal, DateTimeOffset now)
    {
        using var ed = StrictJson.Parse(envelope); var e = ed.RootElement; StrictJson.Exact(e, "protocol", "key_id", "payload", "signature"); if (StrictJson.S(e, "protocol") != "0.1.0" || StrictJson.S(e, "key_id") != "manager-v1" || key.KeySize < 3072) throw new AgentException(); var bytes = Base64(StrictJson.S(e, "payload")); if (!key.VerifyData(bytes, Base64(StrictJson.S(e, "signature")), HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) throw new AgentException("AEGIS_SIGNATURE_REJECTED");
        using var pd = StrictJson.Parse(bytes); var p = pd.RootElement; StrictJson.Exact(p, "protocol", "job_id", "run_id", "agent_id", "approval_id", "environment_id", "generation", "scenario_id", "scenario_sha256", "profile_sha256", "runner_sha256", "kit_sha256", "payload_sha256", "runner_id", "runner_version", "not_before", "expires_at", "collection_start", "collection_end", "timeout_seconds", "parameters");
        foreach (var n in new[] { "job_id", "run_id", "agent_id", "approval_id" }) { var s = StrictJson.S(p, n); if (!Guid.TryParseExact(s, "D", out var g) || g.ToString() != s) throw new AgentException(); }
        if (StrictJson.S(p, "protocol") != "0.1.0" || StrictJson.S(p, "run_id") != StrictJson.S(p, "job_id") || StrictJson.S(p, "agent_id") != agent || StrictJson.S(p, "environment_id") != environment || !Regex.IsMatch(environment, "\\A[A-Za-z0-9_-]{1,64}\\z") || generation < 1 || StrictJson.I(p, "generation") != generation || StrictJson.S(p, "scenario_id") != "SCN-001" || StrictJson.S(p, "runner_id") != "scn001-safe-demo" || StrictJson.S(p, "runner_version") != "0.3.0") throw new AgentException();
        foreach (var n in new[] { "scenario_sha256", "profile_sha256", "runner_sha256", "kit_sha256", "payload_sha256" }) if (!Regex.IsMatch(StrictJson.S(p, n), "\\A[0-9a-f]{64}\\z") || !pins.TryGetValue(n, out var h) || h != StrictJson.S(p, n)) throw new AgentException();
        var nb = Date(p, "not_before"); var exp = Date(p, "expires_at"); var cs = Date(p, "collection_start"); var ce = Date(p, "collection_end"); var timeout = StrictJson.I(p, "timeout_seconds"); if (timeout < 180 || timeout > 300 || exp <= nb || (exp - nb).TotalSeconds > 300 || now < nb || now >= exp || cs > nb || ce < exp.AddSeconds(timeout) || (ce - cs).TotalSeconds > 900) throw new AgentException();
        var a = p.GetProperty("parameters"); StrictJson.Exact(a, "run_label", "rule_revision", "rule_sha256"); var label = StrictJson.S(a, "run_label"); var revision = StrictJson.S(a, "rule_revision"); var rh = StrictJson.S(a, "rule_sha256"); if (!new[] { "A", "B", "C", "Rehearsal" }.Contains(label) || label == "Rehearsal" && !rehearsal || !new[] { "baseline", "behavioral" }.Contains(revision) || ((label == "A" || label == "B") && revision != "baseline") || label == "C" && revision != "behavioral" || !rules.TryGetValue(revision, out var rule) || rule != rh) throw new AgentException();
        return new(StrictJson.S(p, "job_id"), Hash(bytes), bytes, nb, exp, ce, timeout, label, revision, rh);
    }
}
