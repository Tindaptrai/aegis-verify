using System.Security.Cryptography;

namespace Aegis.Connection.Execution;

public sealed record ExecutionCreation(int ProcessId, long CreationFileTime, long BootTickCount, string ObservedAt);
public sealed record ExecutionJournalEntry(int SchemaVersion, string JobId, string JobSha256, string Envelope,
    string Payload, string Phase, string? StartRequest, string? StartAck, ExecutionCreation? Creation,
    string? Receipt, string? ReceiptAck)
{
    public static ExecutionJournalEntry Received(VerifiedExecutionJob job) => new(1, job.Job.JobId, job.JobSha256,
        Convert.ToBase64String(job.EnvelopeBytes), Convert.ToBase64String(job.PayloadBytes), "received", null, null, null, null, null);
    [System.Text.Json.Serialization.JsonIgnore]
    public SignedJob Job => ExecutionProtocol.Decode<SignedJob>(Convert.FromBase64String(Payload));
}

// Single supervisor owns the process lock; this journal never creates another owner.
public sealed class ExecutionJournal
{
    public const int RecordLimit = 512 * 1024;
    private const int EntryLimit = 64;
    private readonly string directory;
    private readonly object gate = new();
    public ExecutionJournal(string directory)
    {
        if (!Path.IsPathFullyQualified(directory)) throw Invalid();
        this.directory = directory;
        PrivatePaths.CreateDirectory(directory);
    }
    public IReadOnlyList<ExecutionJournalEntry> Entries()
    {
        lock (gate) return InspectExisting(directory);
    }
    internal static IReadOnlyList<ExecutionJournalEntry> InspectExisting(string directory)
    {
        try
        {
            PrivatePaths.Verify(directory, true);
            if (Directory.EnumerateDirectories(directory).Any()) throw Invalid();
            var all = Directory.EnumerateFiles(directory).Take(EntryLimit * 3 + 1).ToArray();
            if (all.Length > EntryLimit * 3) throw Invalid();
            long total = 0;
            foreach (var candidate in all)
            {
                PrivatePaths.Verify(candidate, false);
                var name = Path.GetFileName(candidate); var length = new FileInfo(candidate).Length;
                var temporary = System.Text.RegularExpressions.Regex.IsMatch(name, "\\A\\.journal-[0-9a-f]{32}\\.tmp\\z");
                var extension = Path.GetExtension(name);
                if (!temporary && (extension is not (".json" or ".log") || !Protocol.Uuid(Path.GetFileNameWithoutExtension(name)))) throw Invalid();
                if (length > (extension == ".log" ? 1024 * 1024 : RecordLimit)) throw Invalid();
                total += length;
            }
            if (total > EntryLimit * (2L * RecordLimit + 1024 * 1024)) throw Invalid();
            var paths = all.Where(p => Path.GetExtension(p) == ".json").ToArray();
            if (paths.Length > EntryLimit) throw Invalid();
            var entries = new List<ExecutionJournalEntry>();
            foreach (var path in paths)
            {
                PrivatePaths.Verify(path, false);
                using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                if (file.Length is <= 0 or > RecordLimit) throw Invalid();
                var raw = new byte[(int)file.Length]; file.ReadExactly(raw);
                var entry = ExecutionProtocol.Decode<ExecutionJournalEntry>(raw, RecordLimit);
                Validate(entry);
                if (Path.GetFileName(path) != entry.JobId + ".json") throw Invalid();
                entries.Add(entry);
            }
            return entries;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or FormatException)
        { throw Invalid(); }
    }
    public void Transition(string jobId, string? expectedPhase, ExecutionJournalEntry nextEntry)
    {
        lock (gate)
        {
            var entries = Entries(); var old = entries.SingleOrDefault(e => e.JobId == jobId);
            if (jobId != nextEntry.JobId || old?.Phase != expectedPhase || old == null && (expectedPhase != null || entries.Count >= EntryLimit)) throw Invalid();
            Validate(nextEntry);
            if (old == null ? nextEntry.Phase != "received" : !Allowed(old.Phase, nextEntry.Phase)) throw Invalid();
            if (old != null && (old.Envelope != nextEntry.Envelope || old.Payload != nextEntry.Payload || old.JobSha256 != nextEntry.JobSha256 ||
                old.StartRequest != null && old.StartRequest != nextEntry.StartRequest || old.StartAck != null && old.StartAck != nextEntry.StartAck ||
                old.Creation != null && old.Creation != nextEntry.Creation || old.Receipt != null && old.Receipt != nextEntry.Receipt)) throw Invalid();
            var bytes = ExecutionProtocol.CanonicalBytes(nextEntry);
            if (bytes.Length > RecordLimit) throw Invalid();
            var path = Path.Combine(directory, jobId + ".json");
            var temporary = Path.Combine(directory, ".journal-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                PrivatePaths.Verify(directory, true); PrivatePaths.NoLinks(path);
                if (File.Exists(path)) PrivatePaths.Verify(path, false);
                using (var file = PrivatePaths.CreateFile(temporary)) { file.Write(bytes); file.Flush(true); }
                if (OperatingSystem.IsWindows() && File.Exists(path)) File.Replace(temporary, path, null);
                else File.Move(temporary, path, true);
                new DirectoryDurability().Synchronize(directory);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { throw Invalid(); }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
    private static bool Allowed(string from, string to) => (from, to) switch
    {
        ("received", "start_requested") or ("start_requested", "authorized") or ("authorized", "launch_intent") or
        ("launch_intent", "launched") or ("terminal", "accepted") => true,
        ("received" or "start_requested" or "authorized" or "launch_intent" or "launched", "terminal") => true,
        _ => false
    };
    internal static void Validate(ExecutionJournalEntry e)
    {
        try
        {
            var payload = Raw(e.Payload, ExecutionProtocol.RequestLimit);
            var envelope = ExecutionProtocol.Decode<ExecutionEnvelope>(Raw(e.Envelope, ExecutionProtocol.EnvelopeLimit), ExecutionProtocol.EnvelopeLimit);
            var job = ExecutionProtocol.Decode<SignedJob>(payload);
            if (Convert.ToBase64String(payload) != envelope.Payload || e.JobSha256 != ExecutionProfile.Hash(payload) || e.JobId != job.JobId ||
                e.Phase is not ("received" or "start_requested" or "authorized" or "launch_intent" or "launched" or "terminal" or "accepted")) throw Invalid();
            if (e.Phase is "start_requested" or "authorized" or "launch_intent" or "launched" && e.StartRequest == null) throw Invalid();
            if (e.Phase is "authorized" or "launch_intent" or "launched" && e.StartAck == null) throw Invalid();
            if (e.Phase == "launched" && e.Creation == null || e.Phase is "terminal" or "accepted" && e.Receipt == null || e.Phase == "accepted" && e.ReceiptAck == null) throw Invalid();
            if (e.Phase == "received" && e.StartRequest != null || e.Phase is "received" or "start_requested" && e.StartAck != null ||
                e.Phase is "received" or "start_requested" or "authorized" or "launch_intent" && e.Creation != null ||
                e.Phase is not ("terminal" or "accepted") && e.Receipt != null || e.Phase != "accepted" && e.ReceiptAck != null) throw Invalid();
            StartRequest? start = null;
            if (e.StartRequest != null)
            {
                start = ExecutionProtocol.Decode<StartRequest>(Raw(e.StartRequest));
                if (start.DeviceId != job.DeviceId || start.Generation != job.Generation || start.BindingId != job.BindingId || start.BindingRevision != job.BindingRevision || start.JobSha256 != e.JobSha256) throw Invalid();
            }
            if (e.StartAck != null)
            {
                var ack = ExecutionProtocol.StartAck(Raw(e.StartAck));
                if (start == null || ack.JobId != e.JobId || ack.JobSha256 != e.JobSha256 || ack.StartRequestId != start.StartRequestId) throw Invalid();
            }
            if (e.Creation != null && (e.StartAck == null || e.Creation.ProcessId <= 0 || e.Creation.CreationFileTime <= 0 || e.Creation.BootTickCount < 0 || !Protocol.Timestamp(e.Creation.ObservedAt, out _))) throw Invalid();
            ExecutionReceipt? receipt = null;
            if (e.Receipt != null)
            {
                receipt = ExecutionProtocol.Decode<ExecutionReceipt>(Raw(e.Receipt));
                if (receipt.JobId != e.JobId || receipt.JobSha256 != e.JobSha256 || receipt.DeviceId != job.DeviceId || receipt.Generation != job.Generation ||
                    receipt.BindingId != job.BindingId || receipt.BindingRevision != job.BindingRevision || receipt.StartedAt != null && e.Creation == null) throw Invalid();
            }
            if (e.ReceiptAck != null)
            {
                var ack = ExecutionProtocol.ReceiptAck(Raw(e.ReceiptAck));
                if (receipt == null || ack.JobId != e.JobId || ack.JobSha256 != e.JobSha256 || ack.ReceiptId != receipt.ReceiptId) throw Invalid();
            }
        }
        catch (Exception error) when (error is FormatException or ArgumentException or CryptographicException) { throw Invalid(); }
    }
    internal static byte[] Raw(string value, int limit = ExecutionProtocol.RequestLimit)
    {
        if (value.Length > ((limit + 2) / 3) * 4) throw Invalid();
        var raw = Convert.FromBase64String(value);
        if (raw.Length == 0 || raw.Length > limit || Convert.ToBase64String(raw) != value) throw Invalid();
        return raw;
    }
    private static ConnectionException Invalid() => new("execution_journal_invalid");
}
