using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Aegis.Connection;

internal static partial class Program
{
    private static readonly List<(string Name, Func<Task> Run)> Tests = [];
    private static async Task<int> Main(string[] args)
    {
        if (args.Length > 0 && args[0].StartsWith("--provisioning-", StringComparison.Ordinal)) return ProvisioningEntry(args);
        if (args.Length > 0 && args[0] == "--execution-child") return await ExecutionChild(args);
        var nativeGate = args.Length > 0 && args[0] == "--execution-native";
        var requireNative = nativeGate && args.Length == 2 && args[1] == "--require-native";
        if (nativeGate && !(args.Length == 1 || requireNative)) return 2;
        if (args.Length == 2 && args[0] == "--execution-vector") return ExecutionVector(args[1]);
        StateTests();
        ProtocolTests();
        ExecutionProtocolTests();
        ExecutionJournalTests();
        ExecutionCoordinatorTests();
        ExecutionNativeTests();
        ExecutionClientTests();
        ExecutionSupervisorTests();
        ExecutionPreflightTests();
        TransportTests();
        NetworkTests();
        LoopTests();
        CliTests();
        DurabilityTests();
        ServiceHostTests();
        var selected = Tests.Where(t => nativeGate ? t.Name.StartsWith("execution native ", StringComparison.Ordinal) : args.Length == 0 || t.Name.Contains(args[0], StringComparison.OrdinalIgnoreCase)).ToArray();
        int failed = 0;
        foreach (var test in selected)
        {
            try { await test.Run(); Console.WriteLine("PASS " + test.Name); }
            catch (Exception ex) { failed++; Console.WriteLine("FAIL " + test.Name + ": " + ex); }
        }
        Console.WriteLine($"{selected.Length - failed}/{selected.Length} passed");
        if (nativeGate) Console.WriteLine(JsonSerializer.Serialize(new { kind = "execution_native_gate", required = requireNative,
            executed = selected.Length, failed, platform_supported = OperatingSystem.IsWindowsVersionAtLeast(10) && System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X64 }));
        return failed == 0 && selected.Length > 0 ? 0 : 1;
    }
    private static void Test(string name, Action action) => Tests.Add((name, () => { action(); return Task.CompletedTask; }));
    private static void Test(string name, Func<Task> action) => Tests.Add((name, action));
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
    private static void Denied(Action action, string? code = null)
    {
        try { action(); } catch (ConnectionException e) when (code == null || e.Code == code) { return; }
        throw new Exception("Expected rejection" + (code == null ? "" : " " + code));
    }
    private sealed class Scratch : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "aegis-connection-" + Guid.NewGuid().ToString("N"));
        public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, true); }
    }
    private sealed class Issuer : IDisposable
    {
        public RSA Key { get; } = RSA.Create(3072);
        public X509Certificate2 Certificate { get; }
        public Issuer()
        {
            var request = new CertificateRequest("CN=Synthetic harness CA", Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            Certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-90), DateTimeOffset.UtcNow.AddDays(90));
        }
        public EnrollmentResponse Issue(IdentityState state, string? device = null, RSA? foreignKey = null, string? san = null, bool ca = false, string eku = "1.3.6.1.5.5.7.3.2", DateTimeOffset? expiry = null)
        {
            device ??= Guid.NewGuid().ToString();
            using var local = RSA.Create(); local.ImportFromPem(state.PrivateKeyPem);
            var request = new CertificateRequest("CN=AEGIS-Agent-" + device, foreignKey ?? local, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(eku) }, false));
            var names = new SubjectAlternativeNameBuilder(); names.AddUri(new Uri(san ?? "urn:aegis:agent:" + device)); request.CertificateExtensions.Add(names.Build());
            var end = DateTimeOffset.FromUnixTimeSeconds((expiry ?? DateTimeOffset.UtcNow.AddDays(30)).ToUnixTimeSeconds());
            using var cert = request.Create(Certificate, end.AddDays(-30), end, RandomNumberGenerator.GetBytes(16));
            return new("2.0", device, "synthetic-env", 1, cert.ExportCertificatePem(), Certificate.ExportCertificatePem(), end.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"), 15, 60);
        }
        public void Dispose() { Certificate.Dispose(); Key.Dispose(); }
    }
    private static void StateTests()
    {
        Test("state durable pending reload and new code reuses key", () =>
        {
            using var temp = new Scratch(); using var ca = new Issuer(); string key, csr;
            using (var store = StateStore.Acquire(temp.Path)) { var s = store.Prepare("https://manager.invalid", ca.Certificate.ExportCertificatePem()); key = s.PrivateKeyPem; csr = s.CsrPem; }
            using (var store = StateStore.Acquire(temp.Path))
            {
                var s = store.Prepare("https://manager.invalid", ca.Certificate.ExportCertificatePem());
                Check(s.Kind == "pending" && s.PrivateKeyPem == key && s.CsrPem == csr, "pending identity changed");
                using var rsa = RSA.Create(); rsa.ImportFromPem(key); Check(rsa.KeySize == 3072, "wrong key size");
                Check(!store.StatusJson().Contains("PRIVATE KEY"), "status leaked key");
            }
        });
        Test("state exclusive lock denies concurrent owner", () => { using var temp = new Scratch(); using var first = StateStore.Acquire(temp.Path); Denied(() => StateStore.Acquire(temp.Path).Dispose(), "state_locked"); });
        Test("state enrolled refuses overwrite and rejects foreign response", () =>
        {
            using var temp = new Scratch(); using var ca = new Issuer(); using var store = StateStore.Acquire(temp.Path);
            var s = store.Prepare("https://manager.invalid", ca.Certificate.ExportCertificatePem()); using var foreign = RSA.Create(3072);
            Denied(() => store.Promote(ca.Issue(s, foreignKey: foreign)), "identity_invalid");
            Check(store.Read()!.Kind == "pending", "bad cert promoted");
            var response = ca.Issue(s); store.Promote(response);
            Denied(() => store.Prepare("https://manager.invalid", ca.Certificate.ExportCertificatePem()), "already_enrolled");
            Check(store.Read()!.DeviceId == response.DeviceId, "identity overwritten");
            store.Acknowledge(new DateTimeOffset(2026, 10, 24, 1, 2, 3, TimeSpan.Zero));
            var status = store.StatusJson(); Check(status.Contains("2026-10-24T01:02:03") && !status.Contains("online", StringComparison.OrdinalIgnoreCase), "invalid status authority");
        });
        Test("state certificate SAN EKU CA expiry issuer bindings fail closed", () =>
        {
            using var temp = new Scratch(); using var ca = new Issuer(); using var otherCa = new Issuer(); using var store = StateStore.Acquire(temp.Path);
            var s = store.Prepare("https://manager.invalid", ca.Certificate.ExportCertificatePem());
            var valid = ca.Issue(s);
            foreach (var bad in new[] { ca.Issue(s, san: "urn:aegis:agent:" + Guid.NewGuid()), ca.Issue(s, ca: true), ca.Issue(s, eku: "1.3.6.1.5.5.7.3.1"), valid with { IssuerPem = otherCa.Certificate.ExportCertificatePem() }, valid with { ExpiresAt = "2000-01-01T00:00:00Z" }, valid with { Generation = 2 }, valid with { EnvironmentId = "../bad" } })
                Denied(() => store.Promote(bad), "identity_invalid");
        });
        Test("state malformed and unknown fields never overwritten", () =>
        {
            using var temp = new Scratch(); using (var store = StateStore.Acquire(temp.Path)) { }
            var file = System.IO.Path.Combine(temp.Path, "state.json");
            File.WriteAllText(file, "{\"kind\":\"pending\",\"kind\":\"enrolled\"}");
            Denied(() => { using var store = StateStore.Acquire(temp.Path); store.Read(); }, "state_invalid");
            Check(File.ReadAllText(file).Contains("enrolled"), "malformed bytes overwritten");
        });
        Test("state insecure and symlink paths denied", () =>
        {
            using var temp = new Scratch(); using var target = new Scratch(); Directory.CreateDirectory(target.Path);
            Directory.CreateSymbolicLink(temp.Path, target.Path);
            Denied(() => StateStore.Acquire(temp.Path).Dispose(), "state_invalid");
            Directory.Delete(temp.Path);
            Directory.CreateDirectory(temp.Path);
            if (OperatingSystem.IsLinux()) { File.SetUnixFileMode(temp.Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.OtherRead); Denied(() => StateStore.Acquire(temp.Path).Dispose(), "state_invalid"); }
            else if (OperatingSystem.IsWindows())
            {
                var info = new DirectoryInfo(temp.Path); var acl = info.GetAccessControl();
                acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-1-0"), System.Security.AccessControl.FileSystemRights.Read, System.Security.AccessControl.AccessControlType.Allow)); info.SetAccessControl(acl);
                Denied(() => StateStore.Acquire(temp.Path).Dispose(), "state_invalid");
            }
        });
        Test("state atomic write failure preserves complete pending identity", () =>
        {
            using var temp = new Scratch(); using var ca = new Issuer(); using var store = StateStore.Acquire(temp.Path);
            var s = store.Prepare("https://manager.invalid", ca.Certificate.ExportCertificatePem());
            var file = System.IO.Path.Combine(temp.Path, "state.json"); var before = File.ReadAllBytes(file);
            // A real filesystem sharing conflict denies replacement on Windows. On Linux validate-before-write is the failure boundary.
            if (OperatingSystem.IsWindows()) { using var held = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read); Denied(() => store.Promote(ca.Issue(s)), "state_invalid"); }
            else Denied(() => store.Promote(ca.Issue(s) with { DeviceId = "invalid" }), "identity_invalid");
            Check(File.ReadAllBytes(file).SequenceEqual(before), "atomic failure destroyed identity");
            if (OperatingSystem.IsWindows())
            {
                // Native test/status readers must allow replacement while retaining
                // their complete old snapshot; never retry or weaken writer failures.
                var protectedAcl = FileSystemAclExtensions.GetAccessControl(new FileInfo(file)).GetSecurityDescriptorBinaryForm();
                using var shared = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                store.Promote(ca.Issue(s));
                Check(store.Read()!.Kind == "enrolled" && store.Read()!.PrivateKeyPem == s.PrivateKeyPem, "shared reader blocked identity publication");
                using var previous = new MemoryStream(); shared.CopyTo(previous);
                Check(previous.ToArray().SequenceEqual(before), "shared reader lost complete old snapshot");
                Check(FileSystemAclExtensions.GetAccessControl(new FileInfo(file)).GetSecurityDescriptorBinaryForm().SequenceEqual(protectedAcl), "replacement changed protected snapshot ACL");
            }
        });
        Test("state retire match archive failure lock and complete preservation", () =>
        {
            using var temp = new Scratch(); using var ca = new Issuer(); using var store = StateStore.Acquire(temp.Path);
            var pending = store.Prepare("https://manager.invalid", ca.Certificate.ExportCertificatePem()); var response = ca.Issue(pending); store.Promote(response);
            Denied(() => store.Retire(Guid.NewGuid().ToString()), "identity_mismatch");
            var retired = System.IO.Path.Combine(temp.Path, "retired"); File.WriteAllText(retired, "blocked");
            Denied(() => store.Retire(response.DeviceId), "state_invalid"); Check(store.Read()!.DeviceId == response.DeviceId, "archive failure lost identity"); File.Delete(retired);
            var archive = store.Retire(response.DeviceId); Check(store.Read() == null, "retired identity active");
            using var archived = JsonDocument.Parse(File.ReadAllBytes(archive));
            Check(archived.RootElement.GetProperty("private_key_pem").GetString() == pending.PrivateKeyPem && archived.RootElement.GetProperty("certificate_pem").GetString() == response.CertificatePem && archived.RootElement.GetProperty("server_ca_pem").GetString() == pending.ServerCaPem, "archive missing complete identity");
            Check(store.Prepare("https://manager.invalid", ca.Certificate.ExportCertificatePem()).PrivateKeyPem != pending.PrivateKeyPem, "fresh connect reused retired key");
        });
    }
    private static void ProtocolTests()
    {
        Test("protocol exact wire requests and strict closed responses", () =>
        {
            var state = new IdentityState("pending", "https://manager.invalid", "ca", "key", "csr", "synthetic-host", "linux", "x64", "0.1.0", "11111111-1111-4111-8111-111111111111", "env", 1);
            var request = Encoding.UTF8.GetString(Protocol.EnrollmentRequest(state, new string('a', 64)));
            using var doc = JsonDocument.Parse(request); Check(doc.RootElement.EnumerateObject().Count() == 7 && doc.RootElement.GetProperty("pairing_code").GetString() == new string('a', 64) && doc.RootElement.GetProperty("protocol").GetString() == "2.0", "wire request differs");
            Check(Encoding.UTF8.GetString(Protocol.HeartbeatRequest(state)) == "{\"protocol\":\"2.0\",\"device_id\":\"11111111-1111-4111-8111-111111111111\",\"generation\":1}", "heartbeat wire differs");
            var heartbeat = "{\"protocol\":\"2.0\",\"server_time\":\"2026-10-24T01:02:03Z\",\"heartbeat_seconds\":15,\"offline_after_seconds\":60}";
            Check(Protocol.Heartbeat(Encoding.UTF8.GetBytes(heartbeat)).ServerTime == "2026-10-24T01:02:03Z", "response parse");
            foreach (var bad in new[] { heartbeat.Replace("15", "16"), heartbeat.Replace("\"2.0\"", "\"1.0\""), heartbeat.Replace("\"protocol\":", "\"unknown\":0,\"protocol\":"), heartbeat.Replace("\"protocol\":", "\"protocol\":\"2.0\",\"protocol\":"), heartbeat.Replace("2026-10-24T01:02:03Z", "2026-10-24"), "[]", new string(' ', 16385) }) Denied(() => Protocol.Heartbeat(Encoding.UTF8.GetBytes(bad)), "response_invalid");
        });
        Test("protocol origin rejects credentials path query fragment insecure scheme", () =>
        {
            Check(Protocol.Origin("https://MANAGER.invalid:8443").AbsoluteUri == "https://manager.invalid:8443/", "origin normalization");
            foreach (var origin in new[] { "http://manager.invalid", "https://user:pass@manager.invalid", "https://manager.invalid/path", "https://manager.invalid?x=1", "https://manager.invalid#part", "https://manager.invalid/../", "https://manager.invalid\\path", "https://manager.invalid/", " https://manager.invalid" }) Denied(() => Protocol.Origin(origin), "configuration_invalid");
        });
    }
    private static partial void TransportTests();
    private static partial void LoopTests();
}
