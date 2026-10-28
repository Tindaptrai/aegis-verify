using System.Text.Json;
using System.Security.Cryptography;
namespace Aegis.Agent;

public sealed class Configuration : IDisposable
{
    readonly JsonDocument document; public JsonElement Root => document.RootElement; public JsonElement Catalog => Root.GetProperty("catalog");
    public string S(string n) => StrictJson.S(Root, n); public string C(string n) => StrictJson.S(Catalog, n);
    public Dictionary<string, string> Pins { get; } = new(); public Dictionary<string, string> Rules { get; } = new(); public RSA Key { get; } = RSA.Create();
    public Configuration(string path) { document = StrictJson.Parse(Paths.Read(path)); StrictJson.Exact(Root, "manager_url", "agent_id", "environment_id", "generation", "client_certificate_sha256", "signing_public_key_path", "spool_directory", "catalog"); StrictJson.Exact(Catalog, "scenario_path", "profile_path", "runner_path", "kit_directory", "run_directory", "expected_computer_name", "allow_rehearsal", "scenario_sha256", "profile_sha256", "runner_sha256", "kit_sha256", "payload_sha256", "baseline_sha256", "behavioral_sha256"); Transport.ValidateOrigin(S("manager_url")); if (C("expected_computer_name") != Environment.MachineName) throw new AgentException("AEGIS_WRONG_HOST"); foreach (var n in new[] { "scenario_sha256", "profile_sha256", "runner_sha256", "kit_sha256", "payload_sha256" }) Pins[n] = C(n); foreach (var n in new[] { "baseline", "behavioral" }) Rules[n] = C(n + "_sha256"); Key.ImportFromPem(System.Text.Encoding.UTF8.GetString(Paths.Read(S("signing_public_key_path")))); CheckFiles(); }
    public VerifiedJob Verify(byte[] bytes) => Protocol.Verify(bytes, Key, S("agent_id"), S("environment_id"), StrictJson.I(Root, "generation"), Pins, Rules, Catalog.GetProperty("allow_rehearsal").GetBoolean(), DateTimeOffset.UtcNow);
    void Check(string path, string hash) { if (Protocol.Hash(Paths.Read(path)) != hash) throw new AgentException("AEGIS_CATALOG_HASH_MISMATCH"); }
    public void CheckFiles() { Check(C("scenario_path"), Pins["scenario_sha256"]); Check(C("profile_path"), Pins["profile_sha256"]); Check(C("runner_path"), Pins["runner_sha256"]); var kit = C("kit_directory"); var manifest = Path.Combine(kit, "kit.json"); Check(manifest, Pins["kit_sha256"]); using var d = StrictJson.Parse(Paths.Read(manifest)); var k = d.RootElement; if (StrictJson.S(k, "target_host") != C("expected_computer_name") || StrictJson.S(k, "lab_directory") != kit || StrictJson.S(k, "payload_sha256") != Pins["payload_sha256"] || StrictJson.S(k, "kit_version") != "0.3.0" || StrictJson.S(k, "scenario_id") != "SCN-001") throw new AgentException(); foreach (var n in new[] { "lab_update.ps1", "maintenance_check.ps1" }) Check(Path.Combine(kit, n), Pins["payload_sha256"]); foreach (var n in new[] { "baseline", "behavioral" }) Check(Path.Combine(kit, n + ".xml"), Rules[n]); Paths.Local(C("run_directory")); Paths.Local(S("spool_directory")); }
    public void Dispose() { Key.Dispose(); document.Dispose(); }
}
