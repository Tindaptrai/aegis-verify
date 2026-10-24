using System.Text.Json;
using Aegis.Connection;

internal static partial class Program
{
    private sealed class DirectoryBarrier(Action<string> synchronize) : IDirectoryDurability
    {
        public void Synchronize(string directory) => synchronize(directory);
    }
    private static string[] Hierarchy(string path)
    {
        var paths = new List<string>();
        for (var info = new DirectoryInfo(path); info != null; info = info.Parent) paths.Add(info.FullName);
        return paths.ToArray();
    }
    private static void DurabilityTests()
    {
        Test("state durability publishes new directory hierarchy and pending snapshot before return", () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); var calls = new List<string>(); bool publishing = false;
            var barrier = new DirectoryBarrier(path =>
            {
                calls.Add(path);
                if (publishing)
                {
                    using var saved = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(temp.Path, "state.json")));
                    Check(saved.RootElement.GetProperty("kind").GetString() == "pending" && saved.RootElement.GetProperty("private_key_pem").GetString()!.StartsWith("-----BEGIN PRIVATE KEY-----"), "directory synchronized before key publication");
                }
            });
            using var store = StateStore.Acquire(temp.Path, barrier);
            Check(calls.SequenceEqual(Hierarchy(temp.Path)), "new state hierarchy not synchronized before use");
            calls.Clear(); publishing = true; var state = store.Prepare("https://manager.invalid", issuer.Certificate.ExportCertificatePem());
            Check(calls.SequenceEqual(new[] { temp.Path }) && state.PrivateKeyPem == store.Read()!.PrivateKeyPem, "pending publication returned before directory durability");
        });
        Test("state durability failed pending publication retains key and retries barrier on reuse", () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); bool fail = false; int barriers = 0;
            using var store = StateStore.Acquire(temp.Path, new DirectoryBarrier(_ => { barriers++; if (fail) throw new IOException("synthetic directory sync failure"); }));
            barriers = 0; fail = true;
            Denied(() => store.Prepare("https://manager.invalid", issuer.Certificate.ExportCertificatePem()), "state_invalid");
            var pending = store.Read()!; Check(pending.Kind == "pending" && barriers == 1, "publication failure lost pending key");
            fail = false; var reused = store.Prepare("https://manager.invalid", issuer.Certificate.ExportCertificatePem());
            Check(reused.PrivateKeyPem == pending.PrivateKeyPem && barriers == 2, "pending reuse bypassed failed durability boundary");
        });
        Test("state durability acquisition failure stops before creating private identity", () =>
        {
            using var temp = new Scratch();
            Denied(() => StateStore.Acquire(temp.Path, new DirectoryBarrier(_ => throw new IOException("synthetic directory sync failure"))).Dispose(), "state_invalid");
            Check(!File.Exists(Path.Combine(temp.Path, "state.json")), "acquisition failure generated private identity");
            var calls = new List<string>(); using var recovered = StateStore.Acquire(temp.Path, new DirectoryBarrier(calls.Add));
            Check(calls.SequenceEqual(Hierarchy(temp.Path)), "retry skipped durability of earlier created directory");
        });
        Test("state durability failed replacement preserves complete same-key identity", () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); bool fail = false;
            using var store = StateStore.Acquire(temp.Path, new DirectoryBarrier(_ => { if (fail) throw new IOException("synthetic directory sync failure"); }));
            var pending = store.Prepare("https://manager.invalid", issuer.Certificate.ExportCertificatePem()); var response = issuer.Issue(pending); fail = true;
            Denied(() => store.Promote(response), "state_invalid");
            var saved = store.Read()!;
            Check(saved.PrivateKeyPem == pending.PrivateKeyPem && saved.CertificatePem == response.CertificatePem && saved.IssuerPem == response.IssuerPem && saved.ServerCaPem == pending.ServerCaPem, "failed synchronization discarded recoverable identity");
        });
        Test("state durability archive barriers fail before active identity removal", () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); bool retiring = false; int step = 0, failStep = 0;
            var source = Path.Combine(temp.Path, "state.json");
            using var store = StateStore.Acquire(temp.Path, new DirectoryBarrier(_ =>
            {
                if (!retiring) return;
                Check(File.Exists(source), "active identity removed before archive hierarchy became durable");
                if (++step == failStep) throw new IOException("synthetic archive directory sync failure");
            }));
            Enroll(store, issuer); var identity = store.Read()!; var original = File.ReadAllBytes(source); retiring = true;
            // Fail archive-directory, retired-parent and state-directory publication independently.
            for (failStep = 1; failStep <= 3; failStep++)
            {
                step = 0; Denied(() => store.Retire(identity.DeviceId!), "state_invalid");
                Check(File.ReadAllBytes(source).SequenceEqual(original) && store.Read()!.PrivateKeyPem == identity.PrivateKeyPem, "archive sync failure altered active identity");
            }
        });
        Test("state durability source unlink is attempted only after complete durable archive", () =>
        {
            using var temp = new Scratch(); using var issuer = new Issuer(); bool retiring = false; var calls = new List<string>(); string? archive = null; byte[] original = [];
            var source = Path.Combine(temp.Path, "state.json");
            using var store = StateStore.Acquire(temp.Path, new DirectoryBarrier(path =>
            {
                if (!retiring) return;
                if (archive == null) archive = Directory.GetFiles(Path.Combine(temp.Path, "retired"), "state.json", SearchOption.AllDirectories).Single();
                Check(File.ReadAllBytes(archive).SequenceEqual(original), "archive was not complete before synchronization");
                if (File.Exists(source)) calls.Add(path);
                else
                {
                    Check(calls.SequenceEqual(Hierarchy(Path.GetDirectoryName(archive)!)) && path == temp.Path, "source removed before entire archive namespace was durable");
                    throw new IOException("synthetic source directory sync failure");
                }
            }));
            Enroll(store, issuer); var state = store.Read()!; original = File.ReadAllBytes(source); retiring = true;
            Denied(() => store.Retire(state.DeviceId!), "state_invalid");
            Check(archive != null && File.ReadAllBytes(archive).SequenceEqual(original), "post-unlink failure lost already durable archive");
        });
        if (OperatingSystem.IsLinux())
        {
            Test("state durability native Linux directory fsync accepts only real directories", () =>
            {
                using var temp = new Scratch(); Directory.CreateDirectory(temp.Path); var durability = new DirectoryDurability(); durability.Synchronize(temp.Path);
                var file = Path.Combine(temp.Path, "file"); File.WriteAllText(file, "synthetic");
                foreach (var bad in new[] { file, Path.Combine(temp.Path, "missing") })
                {
                    try { durability.Synchronize(bad); throw new Exception("native directory syscall accepted invalid target"); } catch (IOException) { }
                }
                var link = Path.Combine(temp.Path, "link"); Directory.CreateSymbolicLink(link, temp.Path);
                try { durability.Synchronize(link); throw new Exception("native directory syscall followed link"); } catch (ConnectionException) { }
                // /dev/null opens successfully but fsync returns EINVAL. This catches a
                // removed/no-op fsync independently from the O_DIRECTORY open checks.
                using var notSynchronizable = File.OpenHandle("/dev/null", FileMode.Open, FileAccess.Read);
                try { DirectoryDurability.FlushDirectory(notSynchronizable); throw new Exception("native fsync failure was ignored"); } catch (IOException) { }
            });
        }
        else Console.WriteLine("SKIP native Linux directory fsync (requires Linux CI)");
    }
}
