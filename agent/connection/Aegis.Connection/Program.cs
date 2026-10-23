using System.Runtime.InteropServices;
using System.Text.Json;

namespace Aegis.Connection;

internal static class Program
{
    internal static async Task<int> Main(string[] args)
    {
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += handler;
        using var term = OperatingSystem.IsLinux() ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => { context.Cancel = true; cancellation.Cancel(); }) : null;
        try { return await RunAsync(args, SecretPrompt.Read, cancellation.Token); }
        finally { Console.CancelKeyPress -= handler; }
    }
    internal static async Task<int> RunAsync(string[] args, Func<string> prompt, CancellationToken token)
    {
        try
        {
            if (args.Length == 0 || args[0] is not ("connect" or "run" or "status" or "retire")) throw new ConnectionException("usage_invalid");
            var command = args[0];
            var expected = command switch { "connect" => new[] { "--manager", "--server-ca", "--state-dir" }, "retire" => ["--state-dir", "--device-id"], _ => ["--state-dir"] };
            var options = new Dictionary<string, string>(StringComparer.Ordinal);
            for (int i = 1; i < args.Length; i += 2)
                if (i + 1 >= args.Length || !expected.Contains(args[i]) || !options.TryAdd(args[i], args[i + 1])) throw new ConnectionException("usage_invalid");
            if (options.Count != expected.Length) throw new ConnectionException("usage_invalid");
            var directory = options["--state-dir"];
            if (command == "run") return await HeartbeatLoop.RunAsync(directory, token);
            if (command == "status") { Console.Out.WriteLine(StateStore.Status(directory)); return 0; }
            using var store = StateStore.Acquire(directory);
            if (command == "retire") { store.Retire(options["--device-id"]); Console.Out.WriteLine(store.StatusJson()); return 0; }
            var caPath = options["--server-ca"];
            if (!Path.IsPathFullyQualified(caPath)) throw new ConnectionException("configuration_invalid");
            PrivatePaths.NoLinks(caPath);
            var file = new FileInfo(caPath);
            if (!file.Exists || file.Length is <= 0 or > 8192) throw new ConnectionException("configuration_invalid");
            var state = store.Prepare(options["--manager"], File.ReadAllText(caPath));
            var code = prompt();
            // Validate before classifying an attempted enrollment. Prompt errors do not send requests.
            var body = Protocol.EnrollmentRequest(state, code); System.Security.Cryptography.CryptographicOperations.ZeroMemory(body);
            using var client = new AgentClient(state);
            try
            {
                var response = await client.EnrollAsync(code, token); store.Promote(response);
            }
            catch (ConnectionException e) when (e.Code == "pairing_denied") { store.MarkFailure("pairing_denied"); throw; }
            catch (Exception e) when (e is ConnectionException or OperationCanceledException)
            {
                store.MarkFailure("enrollment_outcome_unknown");
                if (e is OperationCanceledException) throw;
                throw new ConnectionException("enrollment_outcome_unknown");
            }
            Console.Out.WriteLine(store.StatusJson()); return 0;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { return 0; }
        catch (ConnectionException e) { Console.Error.WriteLine(JsonSerializer.Serialize(new { error = new { code = e.Code } })); return e.Code == "usage_invalid" ? 2 : 3; }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or System.Security.Cryptography.CryptographicException)
        { Console.Error.WriteLine("{\"error\":{\"code\":\"configuration_invalid\"}}"); return 3; }
    }
}
