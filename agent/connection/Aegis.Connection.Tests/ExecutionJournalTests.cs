using Aegis.Connection;
using Aegis.Connection.Execution;
using System.Security.Cryptography;

internal static partial class Program
{
    private static void ExecutionJournalTests()
    {
        Test("execution journal orphan temporary output files consume bounded spool budget", () =>
        {
            using var temp = new Scratch(); var journal = new ExecutionJournal(temp.Path);
            var path = Path.Combine(temp.Path, ".journal-" + Guid.NewGuid().ToString("N") + ".tmp");
            using (var file = PrivatePaths.CreateFile(path)) file.Write(new byte[ExecutionJournal.RecordLimit + 1]);
            Denied(() => journal.Entries());
            Check(File.Exists(path), "unknown private artifacts were silently erased");
        });
        Test("execution journal each transition is atomic across failed and completed publication", () =>
        {
            using var temp = new Scratch(); var (job, _) = ExecutionFixture(); var journal = new ExecutionJournal(temp.Path);
            var entry = ExecutionJournalEntry.Received(job); journal.Transition(entry.JobId, null, entry);
            var start = new StartRequest(ExecutionProtocol.Version, job.Job.DeviceId, 1, job.Job.BindingId, 1, Guid.NewGuid().ToString(), job.JobSha256);
            var created = new ExecutionCreation(42, 1000, 100, ExecutionCoordinator.Stamp(DateTimeOffset.UtcNow));
            foreach (var phase in new[] { "start_requested", "authorized", "launch_intent", "launched", "terminal", "accepted" })
            {
                var next = entry with { Phase = phase };
                if (phase == "start_requested") next = next with { StartRequest = Convert.ToBase64String(ExecutionProtocol.SerializeStart(start)) };
                if (phase == "authorized") next = next with { StartAck = Convert.ToBase64String(ExecutionProtocol.CanonicalBytes(new StartAcknowledgment(ExecutionProtocol.Version, entry.JobId, start.StartRequestId, entry.JobSha256, true))) };
                if (phase == "launched") next = next with { Creation = created };
                if (phase == "terminal") next = next with { Receipt = Convert.ToBase64String(ExecutionCoordinator.Unknown(entry, DateTimeOffset.UtcNow)) };
                if (phase == "accepted")
                {
                    var r = ExecutionProtocol.Decode<ExecutionReceipt>(Convert.FromBase64String(entry.Receipt!));
                    next = next with { ReceiptAck = Convert.ToBase64String(ExecutionProtocol.CanonicalBytes(new ReceiptAcknowledgment(ExecutionProtocol.Version, r.JobId, r.ReceiptId, r.JobSha256, true))) };
                }
                if (OperatingSystem.IsWindows())
                {
                    using var held = new FileStream(Path.Combine(temp.Path, entry.JobId + ".json"), FileMode.Open, FileAccess.Read, FileShare.Read);
                    Denied(() => journal.Transition(entry.JobId, entry.Phase, next));
                    Check(new ExecutionJournal(temp.Path).Entries().Single() == entry, "failed publication changed phase " + phase);
                }
                journal.Transition(entry.JobId, entry.Phase, next);
                Check(new ExecutionJournal(temp.Path).Entries().Single() == next, "completed publication lost phase " + phase); entry = next;
            }
        });
        Test("execution journal phase cannot carry future authorization or receipt bytes", () =>
        {
            using var temp = new Scratch(); var (job, _) = ExecutionFixture(); var journal = new ExecutionJournal(temp.Path);
            var entry = ExecutionJournalEntry.Received(job);
            var receipt = ExecutionCoordinator.Unknown(entry, DateTimeOffset.UtcNow);
            Denied(() => journal.Transition(entry.JobId, null, entry with { Receipt = Convert.ToBase64String(receipt) }));
        });
        Test("execution journal exact bytes survive restart and phase conflicts reject", () =>
        {
            using var temp = new Scratch(); var (job, _) = ExecutionFixture();
            var journal = new ExecutionJournal(temp.Path);
            var entry = ExecutionJournalEntry.Received(job);
            journal.Transition(job.Job.JobId, null, entry);
            var start = new StartRequest(ExecutionProtocol.Version, job.Job.DeviceId, 1, job.Job.BindingId, 1, Guid.NewGuid().ToString(), job.JobSha256);
            var raw = ExecutionProtocol.SerializeStart(start);
            journal.Transition(entry.JobId, "received", entry with { Phase = "start_requested", StartRequest = Convert.ToBase64String(raw) });
            var again = new ExecutionJournal(temp.Path).Entries().Single();
            Check(again.Phase == "start_requested" && Convert.FromBase64String(again.StartRequest!).SequenceEqual(raw), "durable exact request lost");
            Check(Convert.FromBase64String(again.Envelope).SequenceEqual(job.EnvelopeBytes), "envelope rewritten");
            Denied(() => journal.Transition(entry.JobId, "received", entry));
            Denied(() => journal.Transition(entry.JobId, "start_requested", again with { Phase = "authorized", StartAck = Convert.ToBase64String("{}"u8.ToArray()) }));
        });
        Test("execution journal failure before publication preserves old complete phase", () =>
        {
            using var temp = new Scratch(); var (job, _) = ExecutionFixture(); var journal = new ExecutionJournal(temp.Path);
            var entry = ExecutionJournalEntry.Received(job); journal.Transition(entry.JobId, null, entry);
            var path = Path.Combine(temp.Path, entry.JobId + ".json"); var original = File.ReadAllBytes(path);
            if (OperatingSystem.IsWindows())
            {
                using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                var start = ExecutionProtocol.SerializeStart(new(ExecutionProtocol.Version, job.Job.DeviceId, 1, job.Job.BindingId, 1, Guid.NewGuid().ToString(), job.JobSha256));
                Denied(() => journal.Transition(entry.JobId, "received", entry with { Phase = "start_requested", StartRequest = Convert.ToBase64String(start) }));
                Check(File.ReadAllBytes(path).SequenceEqual(original), "failed write destroyed prior phase");
            }
        });
        Test("execution journal rejects corrupt digest unknown fields and oversized record", () =>
        {
            using var temp = new Scratch(); var (job, _) = ExecutionFixture(); var journal = new ExecutionJournal(temp.Path);
            var entry = ExecutionJournalEntry.Received(job); journal.Transition(entry.JobId, null, entry);
            var path = Path.Combine(temp.Path, entry.JobId + ".json"); var raw = File.ReadAllText(path);
            File.WriteAllText(path, raw.Replace(job.JobSha256, new string('b', 64)));
            Denied(() => journal.Entries());
            File.WriteAllText(path, raw.Insert(1, "\"unexpected\":true,")); Denied(() => journal.Entries());
            File.WriteAllBytes(path, new byte[ExecutionJournal.RecordLimit + 1]); Denied(() => journal.Entries());
        });
    }
    private static (VerifiedExecutionJob Job, ExecutionGrant Grant) ExecutionFixture(ExecutionGrant? configured = null)
    {
        var grant = configured ?? PreflightFixture().Item1; var now = DateTimeOffset.UtcNow.AddSeconds(-5); var p = grant.Profile.ArtifactPins;
        var id = Guid.NewGuid().ToString();
        string Stamp(DateTimeOffset v) => v.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
        var job = new SignedJob(ExecutionProtocol.Version, id, id, grant.Installed.DeviceId, grant.Installed.CertificateSha256,
            Guid.NewGuid().ToString(), grant.Profile.EnvironmentId, 1, grant.Installed.BindingId, 1, 1, new string('a',64),
            "SCN-001", "scn001-safe-demo", "0.3.0", p.ScenarioSha256, p.ProfileSha256, p.RunnerSha256, p.KitSha256, p.PayloadSha256,
            Stamp(now), Stamp(now.AddSeconds(120)), Stamp(now.AddSeconds(-30)), Stamp(now.AddSeconds(300)), 180,
            new("A", "baseline", grant.Profile.RulePins.Baseline));
        var payload = ExecutionProtocol.CanonicalBytes(job); using var key = RSA.Create(3072);
        var envelope = ExecutionProtocol.CanonicalBytes(new ExecutionEnvelope(ExecutionProtocol.Version, ExecutionProtocol.KeyId,
            Convert.ToBase64String(payload), Convert.ToBase64String(key.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))));
        grant = grant with { PublicKeySha256 = Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())) };
        return (ExecutionProtocol.Verify(envelope, key, grant, DateTimeOffset.UtcNow), grant);
    }
}
