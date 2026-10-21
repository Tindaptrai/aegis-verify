using System.Text.Json;

namespace Aegis.Agent;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length != 3 && args.Length != 4)
                throw new AgentException("AEGIS_USAGE");
            if (args[0] != "--config")
                throw new AgentException("AEGIS_USAGE");

            using var config = new Configuration(args[1]);
            if (args.Length == 4 && args[2] == "--validate-envelope")
            {
                config.Verify(Paths.Read(args[3]));
                Console.WriteLine("AEGIS_ENVELOPE_VALID");
                return 0;
            }
            if (args.Length != 3 || args[2] != "--once")
                throw new AgentException("AEGIS_USAGE");

            using var journal = new Journal(config.S("spool_directory"));
            using var transport = new Transport(
                config.S("manager_url"), config.S("client_certificate_sha256"));
            foreach (var entry in journal.Entries())
            {
                if (entry.Phase == "accepted")
                    continue;
                var receipt = entry.Receipt;
                if (receipt == null)
                {
                    receipt = RecoverReceipt(entry, DateTimeOffset.UtcNow);
                    journal.Save(entry with { Phase = "terminal", Receipt = receipt });
                }
                await transport.Ack($"/agent/v1/jobs/{entry.JobId}/receipt", receipt, "accepted");
                journal.Save(entry with { Phase = "accepted", Receipt = receipt });
                return 0;
            }

            var envelope = await transport.Post(
                "/agent/v1/poll", "{\"protocol\":\"0.1.0\"}", true);
            if (envelope == null)
                return 0;
            var job = config.Verify(envelope);
            if (journal.Load(job.Id) != null)
                throw new AgentException("AEGIS_DUPLICATE_JOB");
            journal.Record(job, "start_requested");
            await transport.Ack(
                $"/agent/v1/jobs/{job.Id}/start",
                JsonSerializer.Serialize(new { protocol = "0.1.0", payload_sha256 = job.Digest }),
                "authorized");
            journal.Record(job, "launch_intent");

            var started = DateTimeOffset.UtcNow;
            string terminal;
            using var cancellation = new CancellationTokenSource();
            ConsoleCancelEventHandler cancel = (_, e) =>
            {
                e.Cancel = true;
                cancellation.Cancel();
            };
            Console.CancelKeyPress += cancel;
            try
            {
                if (started < job.NotBefore || started >= job.Expires)
                    throw new AgentException();
                config.CheckFiles();
                var exe = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    @"System32\WindowsPowerShell\v1.0\powershell.exe");
                var output = Path.Combine(config.C("run_directory"), job.Id);
                if (Directory.Exists(output) || File.Exists(output))
                    throw new AgentException();
                var arguments = new[]
                {
                    "-NoLogo", "-NoProfile", "-NonInteractive", "-File", config.C("runner_path"),
                    "-KitDirectory", config.C("kit_directory"), "-RunDirectory", output,
                    "-RunId", job.Id, "-RunLabel", job.Label,
                    "-ExpectedComputerName", config.C("expected_computer_name"),
                    "-AppliedRuleRevision", job.Revision, "-AppliedRuleSha256", job.RuleHash,
                    "-Execute"
                };
                var kitDirectory = config.C("kit_directory");
                var log = Path.Combine(config.S("spool_directory"), job.Id + ".log");
                var remaining = LaunchRemaining(job, started, DateTimeOffset.UtcNow);
                var result = OwnedRunner.Run(
                    exe, arguments, kitDirectory, remaining, cancellation.Token, log);
                var finished = DateTimeOffset.UtcNow;
                var overdue = finished > started.AddSeconds(job.Timeout);
                terminal = overdue
                    ? UnknownReceipt(job, started, finished, result.CleanupSucceeded)
                    : Receipt(
                        job.Id, job.Digest,
                        result.ExitCode == 0 && result.CleanupSucceeded ? "succeeded" : "failed",
                        started, finished, result.ExitCode, result.CleanupSucceeded);
            }
            catch
            {
                // An exception provides no observed process launch, even after authorization.
                terminal = UnknownReceipt(job, null, DateTimeOffset.UtcNow, false);
            }
            finally
            {
                Console.CancelKeyPress -= cancel;
            }

            journal.Record(job, "terminal", terminal);
            await transport.Ack($"/agent/v1/jobs/{job.Id}/receipt", terminal, "accepted");
            journal.Record(job, "accepted", terminal);
            return 0;
        }
        catch (AgentException e)
        {
            Console.Error.WriteLine(e.Message);
            return 2;
        }
        catch
        {
            Console.Error.WriteLine("AEGIS_AGENT_FAILED");
            return 3;
        }
    }

    public static string RecoverReceipt(JournalEntry entry, DateTimeOffset now) =>
        entry.Receipt ?? Receipt(entry.JobId, entry.Digest, "execution_unknown", null, now, null, false);

    internal static TimeSpan LaunchRemaining(
        VerifiedJob job, DateTimeOffset started, DateTimeOffset launchClock)
    {
        var remaining = started.AddSeconds(job.Timeout) - launchClock;
        if (launchClock < job.NotBefore || launchClock >= job.Expires || remaining <= TimeSpan.Zero)
            throw new AgentException();
        return remaining;
    }

    internal static string UnknownReceipt(
        VerifiedJob job, DateTimeOffset? observedStart, DateTimeOffset finish, bool cleanup)
    {
        if (observedStart is { } start &&
            (start < job.NotBefore || start >= job.Expires || start > finish))
            observedStart = null;
        return Receipt(job.Id, job.Digest, "execution_unknown", observedStart, finish, null, cleanup);
    }

    public static string Receipt(
        string id, string hash, string state, DateTimeOffset? start,
        DateTimeOffset finish, int? exit, bool cleanup) =>
        JsonSerializer.Serialize(new
        {
            protocol = "0.1.0",
            receipt_id = Guid.NewGuid().ToString(),
            job_id = id,
            payload_sha256 = hash,
            state,
            started_at = start.HasValue ? Protocol.Time(start.Value) : null,
            finished_at = Protocol.Time(finish),
            exit_code = exit,
            cleanup_succeeded = cleanup
        });
}
