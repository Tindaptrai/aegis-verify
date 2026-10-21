using System.Text.Json;
namespace Aegis.Agent;

public sealed record JournalEntry(string JobId, string Digest, string Phase, string Payload, string? Receipt);
public sealed class Journal : IDisposable
{
    readonly string directory; readonly FileStream gate;
    public Journal(string directory) { Paths.Local(directory); Directory.CreateDirectory(directory); this.directory = directory; gate = new FileStream(Path.Combine(directory, "agent.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
    public IEnumerable<JournalEntry> Entries() => Directory.EnumerateFiles(directory, "*.json").Select(p => JsonSerializer.Deserialize<JournalEntry>(File.ReadAllBytes(p)) ?? throw new AgentException()).ToArray();
    public JournalEntry? Load(string id) => Entries().SingleOrDefault(e => e.JobId == id);
    public void Record(VerifiedJob job, string phase, string? receipt = null) => Save(new(job.Id, job.Digest, phase, Convert.ToBase64String(job.Payload), receipt));
    public void Save(JournalEntry entry) { if (!Guid.TryParseExact(entry.JobId, "D", out _)) throw new AgentException(); var path = Path.Combine(directory, entry.JobId + ".json"); Paths.Local(path); var tmp = path + ".tmp"; using (var f = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { JsonSerializer.Serialize(f, entry); f.Flush(true); } File.Move(tmp, path, true); }
    public void Dispose() => gate.Dispose();
}
public static class Paths
{
    public static void Local(string path) { if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal) || path.IndexOf(':', 3) >= 0 || path.Contains('/') || path.Length > 230) throw new AgentException("AEGIS_INVALID_LOCAL_PATH"); var full = Path.GetFullPath(path); if (!string.Equals(full.TrimEnd('\\'), path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) throw new AgentException(); for (var p = full; !string.IsNullOrEmpty(p); p = Path.GetDirectoryName(p)) { if ((File.Exists(p) || Directory.Exists(p)) && (File.GetAttributes(p) & FileAttributes.ReparsePoint) != 0) throw new AgentException("AEGIS_REPARSE_PATH"); } }
    public static byte[] Read(string path) { Local(path); using var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); if (f.Length > 65536) throw new AgentException(); var b = new byte[(int)f.Length]; f.ReadExactly(b); return b; }
}
