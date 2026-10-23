using System.Text.Json;
using System.Diagnostics;
using Aegis.Connection;
using ClientProgram = Aegis.Connection.Program;

internal static partial class Program
{
    private static async Task<(int Exit, string Output, string Error)> Cli(string[] args, Func<string>? prompt = null)
    {
        var oldOut = Console.Out; var oldError = Console.Error; using var output = new StringWriter(); using var error = new StringWriter();
        try { Console.SetOut(output); Console.SetError(error); return (await ClientProgram.RunAsync(args, prompt ?? (() => throw new Exception("unexpected prompt")), CancellationToken.None), output.ToString(), error.ToString()); }
        finally { Console.SetOut(oldOut); Console.SetError(oldError); }
    }
    private static void CliTests()
    {
        Test("CLI strict command surface status pending enrolled and retired never exposes secrets", async () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer();
            var empty = await Cli(["status", "--state-dir", temp.Path]); Check(empty.Exit == 0 && empty.Output.Contains("unconfigured"), "empty status missing");
            using (var store = StateStore.Acquire(temp.Path)) Enroll(store, issuer);
            var status = await Cli(["status", "--state-dir", temp.Path]); Check(status.Exit == 0 && status.Output.Contains("enrolled") && !status.Output.Contains("PRIVATE") && !status.Output.Contains("certificate_pem"), "status leaked or unavailable");
            string id; using (var store = StateStore.Acquire(temp.Path)) id = store.Read()!.DeviceId!;
            var mismatch = await Cli(["retire", "--state-dir", temp.Path, "--device-id", Guid.NewGuid().ToString()]); Check(mismatch.Exit == 3 && mismatch.Error.Contains("identity_mismatch"), "retire mismatch accepted");
            var retire = await Cli(["retire", "--state-dir", temp.Path, "--device-id", id]); Check(retire.Exit == 0, "retire failed");
            var retired = await Cli(["status", "--state-dir", temp.Path]); Check(retired.Output.Contains("unconfigured"), "retirement status wrong");
            foreach (var args in new[] { new[] { "connect", "--state-dir", temp.Path, "--code", new string('a', 64) }, new[] { "run", "--state-dir", temp.Path, "--state-dir", temp.Path }, new[] { "status", "--state-dir", "relative" }, new[] { "status", "--state-dir", temp.Path, "extra" } })
            {
                var result = await Cli(args); Check(result.Exit is 2 or 3 && !result.Output.Contains(new string('a', 64)) && !result.Error.Contains(new string('a', 64)), "invalid arguments accepted/leaked");
            }
        });
        Test("CLI connect one attempt pending outcome recovery and enrolled refusal before prompt", async () =>
        {
            using var temp = new Scratch(); using var caFile = new Scratch(); using var issuer = new Issuer(); Directory.CreateDirectory(caFile.Path);
            var caPath = Path.Combine(caFile.Path, "server-ca.pem"); File.WriteAllText(caPath, issuer.Certificate.ExportCertificatePem()); int attempts = 0;
            await using var unknown = new TlsEndpoint(issuer, (_, _) => { attempts++; return new Reply(201, "{}"); });
            var args = new[] { "connect", "--manager", unknown.Origin, "--server-ca", caPath, "--state-dir", temp.Path };
            var result = await Cli(args, () => new string('a', 64));
            Check(result.Exit == 3 && result.Error.Contains("enrollment_outcome_unknown") && attempts == 1, "unknown enrollment retried or hidden");
            string key; using (var store = StateStore.Acquire(temp.Path)) { var state = store.Read()!; key = state.PrivateKeyPem; Check(state.Kind == "pending" && state.Failure == "enrollment_outcome_unknown", "pending state lost"); }
            var retry = await Cli(args, () => new string('b', 64)); Check(retry.Exit == 3 && attempts == 2, "replacement code not one attempt");
            using (var store = StateStore.Acquire(temp.Path)) { Check(store.Read()!.PrivateKeyPem == key, "replacement key changed"); store.Promote(issuer.Issue(store.Read()!)); }
            var already = await Cli(args); Check(already.Exit == 3 && already.Error.Contains("already_enrolled"), "enrolled connect prompted/overwrote");
        });
        Test("state persisted enrolled certificate binding cannot be bypassed by editing snapshot", () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); using var foreign = new Issuer(); IdentityState state;
            using (var store = StateStore.Acquire(temp.Path)) { Enroll(store, issuer); state = store.Read()!; }
            var file = Path.Combine(temp.Path, "state.json"); var before = File.ReadAllBytes(file);
            var invalid = state with { IssuerPem = foreign.Certificate.ExportCertificatePem() };
            File.WriteAllBytes(file, JsonSerializer.SerializeToUtf8Bytes(invalid, Protocol.Json));
            Denied(() => StateStore.Acquire(temp.Path).Dispose(), "state_invalid");
            File.WriteAllBytes(file, before);
        });
        Test("CLI status reads atomic snapshot while service holds mutation lock", async () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); using var store = StateStore.Acquire(temp.Path); Enroll(store, issuer);
            var status = await Cli(["status", "--state-dir", temp.Path]);
            Check(status.Exit == 0 && status.Output.Contains(store.Read()!.DeviceId!), "active service blocked status");
            var retire = await Cli(["retire", "--state-dir", temp.Path, "--device-id", store.Read()!.DeviceId!]); Check(retire.Exit == 3 && retire.Error.Contains("state_locked"), "active identity retirement accepted");
        });
        Test("state expired complete identity remains readable and retireable", async () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); IdentityState pending;
            using (var store = StateStore.Acquire(temp.Path)) pending = store.Prepare("https://manager.invalid", issuer.Certificate.ExportCertificatePem());
            var response = issuer.Issue(pending, expiry: DateTimeOffset.UtcNow.AddDays(-1));
            var expired = pending with { Kind = "enrolled", DeviceId = response.DeviceId, EnvironmentId = response.EnvironmentId, Generation = 1, CertificatePem = response.CertificatePem, IssuerPem = response.IssuerPem, ExpiresAt = response.ExpiresAt };
            File.WriteAllBytes(Path.Combine(temp.Path, "state.json"), JsonSerializer.SerializeToUtf8Bytes(expired, Protocol.Json));
            var status = await Cli(["status", "--state-dir", temp.Path]); Check(status.Exit == 0 && status.Output.Contains(response.DeviceId), "expired identity unreadable");
            var run = await Cli(["run", "--state-dir", temp.Path]); Check(run.Exit == 3, "expired identity ran");
            using var recovered = StateStore.Acquire(temp.Path); Check(recovered.Read()!.Failure == "identity_expired", "expiry status absent"); recovered.Retire(response.DeviceId); Check(recovered.Read() == null, "expired retirement failed");
        });
        Test("state status refuses file masquerading as directory", () =>
        {
            using var temp = new Scratch(); File.WriteAllText(temp.Path, "synthetic obstruction");
            try { Denied(() => StateStore.Status(temp.Path), "state_invalid"); } finally { File.Delete(temp.Path); }
        });
        Test("CLI real child redirected stdin bounds secrets one attempt and pending key preservation", async () =>
        {
            using var temp = new Scratch(); using var publicCa = new Scratch(); using var issuer = new Issuer(); Directory.CreateDirectory(publicCa.Path);
            var caPath = Path.Combine(publicCa.Path, "server-ca.pem"); File.WriteAllText(caPath, issuer.Certificate.ExportCertificatePem()); int requests = 0;
            await using var endpoint = new TlsEndpoint(issuer, (_, _) => { requests++; return new Reply(201, "{}"); });
            string key;
            using (var store = StateStore.Acquire(temp.Path)) key = store.Prepare(endpoint.Origin, issuer.Certificate.ExportCertificatePem()).PrivateKeyPem;
            async Task<(int Exit, string Output, string Error)> Child(string input)
            {
                var start = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
                foreach (var value in new[] { typeof(ClientProgram).Assembly.Location, "connect", "--manager", endpoint.Origin, "--server-ca", caPath, "--state-dir", temp.Path }) start.ArgumentList.Add(value);
                Check(!start.ArgumentList.Any(v => v.Contains(new string('a', 64))), "code in process arguments");
                using var child = Process.Start(start) ?? throw new Exception("could not start CLI");
                var output = child.StandardOutput.ReadToEndAsync(); var error = child.StandardError.ReadToEndAsync();
                try { await child.StandardInput.WriteAsync(input); await child.StandardInput.FlushAsync(); } catch (IOException) { }
                child.StandardInput.Close();
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                try { await child.WaitForExitAsync(deadline.Token); }
                catch { child.Kill(entireProcessTree: true); throw; }
                return (child.ExitCode, await output, await error);
            }
            foreach (var input in new[] { new string('a', 64) + "\n", new string('b', 64) + "\r\n", new string('c', 64) })
            {
                var before = requests; var result = await Child(input);
                Check(result.Exit == 3 && result.Error.Contains("enrollment_outcome_unknown") && requests == before + 1, "stdin enrollment did not make exactly one attempt");
                Check(!result.Output.Contains(input.TrimEnd()) && !result.Error.Contains(input.TrimEnd()), "stdin code echoed");
                using var store = StateStore.Acquire(temp.Path); Check(store.Read()!.Kind == "pending" && store.Read()!.PrivateKeyPem == key, "stdin outcome changed pending identity");
            }
            foreach (var input in new[] { new string('d', 65) + "\n", new string('g', 64) + "\n", new string('a', 64) + "\nextra\n", "short\n" })
            {
                var before = requests; var result = await Child(input);
                Check(result.Exit == 3 && result.Error.Contains("pairing_code_invalid") && requests == before, "malformed/oversized stdin sent request");
                Check(!result.Output.Contains(input.TrimEnd()) && !result.Error.Contains(input.TrimEnd()), "invalid stdin echoed");
            }
        });
    }
}
