namespace Aegis.Agent;

public sealed record RunResult(int? ExitCode, bool CleanupSucceeded);
public static class OwnedRunner
{
    public static RunResult Run(string executable, string[] arguments, string workingDirectory, TimeSpan timeout, CancellationToken cancellation, string log)
    {
        if (!OperatingSystem.IsWindows()) throw new AgentException("AEGIS_WINDOWS_REQUIRED");
        Paths.Local(executable); Paths.Local(workingDirectory); Paths.Local(log);
        using var output = new FileStream(log, FileMode.CreateNew, FileAccess.Write, FileShare.Read); var sync = new object(); var written = 0;
        using var job = new OwnedJob(); using var child = NativeChild.Start(job, executable, arguments, text => { lock (sync) { var b = System.Text.Encoding.UTF8.GetBytes(text); var count = Math.Min(b.Length, 1048576 - written); if (count > 0) { output.Write(b, 0, count); written += count; } } }, workingDirectory);
        var clock = System.Diagnostics.Stopwatch.StartNew(); while (!child.HasExited && clock.Elapsed < timeout && !cancellation.IsCancellationRequested) Thread.Sleep(50);
        int? exit = child.HasExited ? child.ExitCode : null;
        // Explicitly terminate the entire owned job, then query until no descendants remain.
        var cleanup = job.TerminateAndWait(); child.DrainOutput(); return new(exit, cleanup);
    }
}
