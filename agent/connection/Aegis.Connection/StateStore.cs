using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Aegis.Connection;

public sealed class ConnectionException(string code, bool transient = false, Exception? cause = null) : Exception(code, cause)
{
    public string Code { get; } = code;
    public bool Transient { get; } = transient;
}

public sealed record IdentityState(
    string Kind, string ManagerOrigin, string ServerCaPem, string PrivateKeyPem, string CsrPem,
    string Hostname, string Os, string Architecture, string AgentVersion,
    string? DeviceId = null, string? EnvironmentId = null, int? Generation = null,
    string? CertificatePem = null, string? IssuerPem = null, string? ExpiresAt = null,
    string? LastAcknowledgedAt = null, string? Failure = null);

public sealed class StateStore : IDisposable
{
    private readonly string directory;
    private readonly FileStream? processLock;
    private readonly IDirectoryDurability durability;
    private bool disposed;
    private string StatePath => Path.Combine(directory, "state.json");
    private StateStore(string directory, FileStream? processLock, IDirectoryDurability durability) { this.directory = directory; this.processLock = processLock; this.durability = durability; }
    public static string Status(string directory)
    {
        if (!Path.IsPathFullyQualified(directory)) throw new ConnectionException("state_invalid");
        PrivatePaths.NoLinks(directory);
        if (File.Exists(directory)) throw new ConnectionException("state_invalid");
        if (!Directory.Exists(directory)) return EmptyStatus;
        using var reader = new StateStore(Path.GetFullPath(directory), null, new DirectoryDurability());
        return reader.StatusJson();
    }
    private static readonly string EmptyStatus = JsonSerializer.Serialize(new { device_id = (string?)null, environment_id = (string?)null, generation = (int?)null, certificate_expires_at = (string?)null, manager_origin = (string?)null, last_acknowledged_at = (string?)null, state = "unconfigured" });
    public static StateStore Acquire(string directory) => Acquire(directory, new DirectoryDurability());
    internal static StateStore Acquire(string directory, IDirectoryDurability durability)
    {
        FileStream? held = null;
        try
        {
            if (!Path.IsPathFullyQualified(directory)) throw new ConnectionException("state_invalid");
            directory = Path.GetFullPath(directory); PrivatePaths.CreateDirectory(directory);
            DirectoryDurability.Hierarchy(directory, durability);
            var lockPath = Path.Combine(directory, "process.lock");
            if (!File.Exists(lockPath)) { try { using var created = PrivatePaths.CreateFile(lockPath); } catch (IOException) when (File.Exists(lockPath)) { } }
            PrivatePaths.Verify(lockPath, false);
            try { held = new FileStream(lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) { throw new ConnectionException("state_locked"); }
            PrivatePaths.Verify(lockPath, false);
            var store = new StateStore(directory, held, durability); store.Read(); return store;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or CryptographicException) { held?.Dispose(); throw new ConnectionException("state_invalid"); }
        catch { held?.Dispose(); throw; }
    }
    public IdentityState? Read()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        try
        {
            PrivatePaths.Verify(directory, true); PrivatePaths.NoLinks(StatePath);
            if (!File.Exists(StatePath)) return null;
            PrivatePaths.Verify(StatePath, false);
            using var file = new FileStream(StatePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (file.Length is <= 0 or > 65536) throw new ConnectionException("state_invalid");
            var bytes = new byte[(int)file.Length]; file.ReadExactly(bytes);
            var state = Protocol.Decode<IdentityState>(bytes, 65536, "state_invalid"); Validate(state); return state;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException or InvalidOperationException) { throw new ConnectionException("state_invalid"); }
    }
    public IdentityState Prepare(string origin, string caPem)
    {
        try
        {
            var uri = Protocol.Origin(origin); using var ca = Certificates.PublicPem(caPem); Certificates.RequireCa(ca);
            var existing = Read();
            if (existing?.Kind == "enrolled") throw new ConnectionException("already_enrolled");
            if (existing != null)
            {
                if (existing.ManagerOrigin != uri.GetLeftPart(UriPartial.Authority) || existing.ServerCaPem != ca.ExportCertificatePem()) throw new ConnectionException("pending_configuration_mismatch");
                // A previous publication can have reached rename but failed its directory
                // barrier. Do not redeem a replacement code until this same key is durable.
                using (var file = new FileStream(StatePath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read)) file.Flush(true);
                durability.Synchronize(directory);
                return existing;
            }
            if (RuntimeInformation.OSArchitecture != Architecture.X64 || !(OperatingSystem.IsWindows() || OperatingSystem.IsLinux())) throw new ConnectionException("configuration_invalid");
            using var key = RSA.Create(3072);
            var csr = new CertificateRequest("CN=AEGIS pending agent", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequestPem();
            var state = new IdentityState("pending", uri.GetLeftPart(UriPartial.Authority), ca.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem(), csr, System.Net.Dns.GetHostName(), OperatingSystem.IsWindows() ? "windows" : "linux", "x64", Protocol.AgentVersion);
            Save(state); return state;
        }
        catch (CryptographicException) { throw new ConnectionException("configuration_invalid"); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { throw new ConnectionException("state_invalid"); }
    }
    public void Promote(EnrollmentResponse response)
    {
        var state = Read() ?? throw new ConnectionException("state_invalid");
        if (state.Kind != "pending") throw new ConnectionException("already_enrolled");
        Certificates.ValidateIdentity(state, response);
        Save(state with { Kind = "enrolled", DeviceId = response.DeviceId, EnvironmentId = response.EnvironmentId, Generation = response.Generation, CertificatePem = response.CertificatePem, IssuerPem = response.IssuerPem, ExpiresAt = response.ExpiresAt, Failure = null });
    }
    public void Acknowledge(DateTimeOffset now)
    {
        var state = Read() ?? throw new ConnectionException("state_invalid");
        if (state.Kind != "enrolled") throw new ConnectionException("enrollment_pending");
        Save(state with { LastAcknowledgedAt = now.ToUniversalTime().ToString("O"), Failure = null });
    }
    public void MarkFailure(string code)
    {
        if (!Failures.Contains(code)) throw new ConnectionException("state_invalid");
        Save((Read() ?? throw new ConnectionException("state_invalid")) with { Failure = code });
    }
    public string StatusJson()
    {
        var state = Read();
        return JsonSerializer.Serialize(new { device_id = state?.DeviceId, environment_id = state?.EnvironmentId, generation = state?.Generation, certificate_expires_at = state?.ExpiresAt, manager_origin = state?.ManagerOrigin, last_acknowledged_at = state?.LastAcknowledgedAt, state = state?.Failure ?? state?.Kind ?? "unconfigured" });
    }
    public string Retire(string deviceId)
    {
        var state = Read() ?? throw new ConnectionException("state_invalid");
        if (state.Kind != "enrolled" || !Protocol.Uuid(deviceId) || state.DeviceId != deviceId) throw new ConnectionException("identity_mismatch");
        try
        {
            var archiveRoot = Path.Combine(directory, "retired"); PrivatePaths.CreateDirectory(archiveRoot);
            var archiveDirectory = Path.Combine(archiveRoot, deviceId + "-" + Guid.NewGuid().ToString("N")); PrivatePaths.CreateDirectory(archiveDirectory);
            var archive = Path.Combine(archiveDirectory, "state.json");
            PrivatePaths.Verify(StatePath, false);
            // Preserve the active identity until a complete archive and its entire
            // namespace are durable. Cross-directory rename alone cannot provide this
            // guarantee when a later fsync fails or power is lost between barriers.
            using (var source = new FileStream(StatePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var destination = PrivatePaths.CreateFile(archive))
            {
                if (source.Length is <= 0 or > 65536) throw new ConnectionException("state_invalid");
                var bytes = new byte[(int)source.Length]; source.ReadExactly(bytes);
                destination.Write(bytes); destination.Flush(true);
            }
            DirectoryDurability.Hierarchy(archiveDirectory, durability);
            File.Delete(StatePath);
            // If this final barrier fails, the already durable archive remains intact.
            durability.Synchronize(directory);
            return archive;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { throw new ConnectionException("state_invalid"); }
    }
    private static readonly HashSet<string> Failures = ["enrollment_outcome_unknown", "pairing_denied", "identity_denied", "identity_expired", "response_invalid"];
    private static void Validate(IdentityState state)
    {
        try
        {
            if (state.Kind is not ("pending" or "enrolled") || Protocol.Origin(state.ManagerOrigin).GetLeftPart(UriPartial.Authority) != state.ManagerOrigin || state.Hostname.Length is < 1 or > 255 || state.Hostname.Any(char.IsControl) || state.Os is not ("windows" or "linux") || state.Architecture != "x64" || state.AgentVersion is not ("0.1.0" or "0.2.0") || state.Failure != null && !Failures.Contains(state.Failure) || state.LastAcknowledgedAt != null && !DateTimeOffset.TryParse(state.LastAcknowledgedAt, out _)) throw new CryptographicException();
            using var ca = Certificates.PublicPem(state.ServerCaPem);
            // Persisted expired trust/identity must still be readable for status and explicit retirement.
            if (!ca.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority)) throw new CryptographicException();
            using var key = RSA.Create(); key.ImportFromPem(state.PrivateKeyPem);
            if (key.KeySize != 3072 || key.ExportPkcs8PrivateKeyPem() != state.PrivateKeyPem) throw new CryptographicException();
            var csr = CertificateRequest.LoadSigningRequestPem(state.CsrPem, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.Default, RSASignaturePadding.Pkcs1);
            if (!csr.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo())) throw new CryptographicException();
            if (state.Kind == "pending")
            {
                if (state.DeviceId != null || state.EnvironmentId != null || state.Generation != null || state.CertificatePem != null || state.IssuerPem != null || state.ExpiresAt != null || state.LastAcknowledgedAt != null) throw new CryptographicException();
            }
            else
            {
                if (state.DeviceId == null || state.EnvironmentId == null || state.CertificatePem == null || state.IssuerPem == null || state.ExpiresAt == null || state.Generation != 1 || !Protocol.Uuid(state.DeviceId) || !Protocol.Environment(state.EnvironmentId) || !Protocol.Timestamp(state.ExpiresAt, out var expiry)) throw new CryptographicException();
                using var cert = Certificates.PublicPem(state.CertificatePem); using var issuer = Certificates.PublicPem(state.IssuerPem); using var publicKey = cert.GetRSAPublicKey();
                if (publicKey == null || !publicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(key.ExportSubjectPublicKeyInfo()) || expiry != new DateTimeOffset(cert.NotAfter.ToUniversalTime())) throw new CryptographicException();
                Certificates.ValidateIdentity(state, new EnrollmentResponse("2.0", state.DeviceId, state.EnvironmentId, 1, state.CertificatePem, state.IssuerPem, state.ExpiresAt, 15, 60), allowExpired: true);
            }
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException or ConnectionException or NullReferenceException) { throw new ConnectionException("state_invalid"); }
    }
    private void Save(IdentityState state)
    {
        if (processLock == null) throw new ConnectionException("state_locked");
        Validate(state);
        var temporary = Path.Combine(directory, ".state-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            PrivatePaths.Verify(directory, true); PrivatePaths.NoLinks(StatePath);
            if (File.Exists(StatePath)) PrivatePaths.Verify(StatePath, false);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(state, Protocol.Json);
            if (bytes.Length > 65536) throw new ConnectionException("state_invalid");
            using (var file = PrivatePaths.CreateFile(temporary)) { file.Write(bytes); file.Flush(true); }
            // Windows MoveFileEx replacement can fail with access denied even
            // when an active status reader grants FILE_SHARE_DELETE. ReplaceFile
            // preserves atomic publication and the verified destination ACL while
            // allowing that reader to finish its complete previous snapshot.
            if (OperatingSystem.IsWindows() && File.Exists(StatePath)) File.Replace(temporary, StatePath, null);
            else File.Move(temporary, StatePath, true);
            durability.Synchronize(directory);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) { throw new ConnectionException("state_invalid"); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public void Dispose() { if (!disposed) { disposed = true; processLock?.Dispose(); } }
}
