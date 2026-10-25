using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;

namespace Aegis.Connection.Execution;

public static class ExecutionProfile
{
    public static ExecutionGrant Load(string profilePath, string grantPath, string signingPublicKeyPath, IdentityState identity)
        => Load(profilePath, grantPath, signingPublicKeyPath, identity, ReadImmutable);

    internal static ExecutionGrant Load(string profilePath, string grantPath, string signingPublicKeyPath, IdentityState identity, Func<string, byte[]> read)
    {
        try
        {
            var profile = ExecutionProtocol.Decode<InstallationProfile>(read(profilePath));
            var installed = ExecutionProtocol.Decode<InstalledGrant>(read(grantPath));
            using var key = PublicKey(read(signingPublicKeyPath));
            var grant = new ExecutionGrant(profile, installed, identity, Hash(key.ExportSubjectPublicKeyInfo()));
            ValidateGrant(grant);
            return grant;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or CryptographicException or ConnectionException)
        { throw new ConnectionException("execution_invalid"); }
    }

    public static RSA LoadSigningKey(string publicKeyPath, ExecutionGrant grant)
    {
        RSA? key = null;
        try
        {
            key = PublicKey(ReadImmutable(publicKeyPath));
            if (Hash(key.ExportSubjectPublicKeyInfo()) != grant.PublicKeySha256) throw new CryptographicException();
            return key;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or CryptographicException or ConnectionException)
        { key?.Dispose(); throw new ConnectionException("execution_invalid"); }
    }
    private static RSA PublicKey(byte[] bytes)
    {
        var text = new UTF8Encoding(false,true).GetString(bytes);
        if (!text.StartsWith("-----BEGIN PUBLIC KEY-----",StringComparison.Ordinal) || text.Contains("PRIVATE",StringComparison.Ordinal)) throw new CryptographicException();
        var key = RSA.Create();
        try { key.ImportFromPem(text); if (key.KeySize != 3072) throw new CryptographicException(); return key; }
        catch { key.Dispose(); throw; }
    }
    internal static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    [SupportedOSPlatform("windows")]
    internal static bool GrantsMutation(FileSystemRights rights)
    {
        // Modify is composite and includes ReadAndExecute: test individual write
        // capabilities so a service's read/execute grant remains admissible.
        const FileSystemRights writes = FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | FileSystemRights.DeleteSubdirectoriesAndFiles;
        return (rights & writes) != 0;
    }
    internal static void ValidateGrant(ExecutionGrant grant)
    {
        var profile = ExecutionProtocol.Decode<InstallationProfile>(ExecutionProtocol.CanonicalBytes(grant.Profile));
        var installed = ExecutionProtocol.Decode<InstalledGrant>(ExecutionProtocol.CanonicalBytes(grant.Installed));
        var identity = grant.Identity;
        if (identity.Kind != "enrolled" || identity.Os != "windows" || identity.Architecture != "x64" || identity.CertificatePem == null ||
            installed.DeviceId != identity.DeviceId || installed.Generation != identity.Generation || profile.EnvironmentId != identity.EnvironmentId ||
            Hash(ExecutionProtocol.CanonicalBytes(profile)) != installed.InstallationProfileSha256 ||
            Hash(ExecutionProtocol.CanonicalBytes(new { profile.ArtifactPins, profile.RulePins })) != installed.ArtifactSetSha256)
            throw new ConnectionException("execution_invalid");
        using var certificate = X509Certificate2.CreateFromPem(identity.CertificatePem);
        if (Hash(certificate.RawData) != installed.CertificateSha256 || !Regex.IsMatch(grant.PublicKeySha256,"\\A[0-9a-f]{64}\\z"))
            throw new ConnectionException("execution_invalid");
    }

    internal static void LocalPath(string path, int limit = 230)
    {
        if (string.IsNullOrEmpty(path) || path.Length > limit || !Regex.IsMatch(path,"\\A[A-Za-z]:\\\\[A-Za-z0-9 _.'+&\\\\-]+\\z")) throw new ConnectionException("execution_invalid");
        foreach (var part in path[3..].Split('\\'))
            if (part.Length == 0 || part is "." or ".." || part != part.Trim() || part.EndsWith('.') ||
                Regex.IsMatch(part,"\\A(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\.|$)",RegexOptions.IgnoreCase)) throw new ConnectionException("execution_invalid");
        if (OperatingSystem.IsWindows() && Path.GetFullPath(path) != path) throw new ConnectionException("execution_invalid");
    }
    internal static byte[] ReadImmutable(string path)
    {
        LocalPath(path);
        if (!OperatingSystem.IsWindows()) throw new ConnectionException("execution_invalid");
        VerifyImmutable(path, false);
        using var file = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if (file.Length is <=0 or >65536) throw new ConnectionException("execution_invalid");
        var bytes = new byte[(int)file.Length]; file.ReadExactly(bytes);
        VerifyImmutable(path, false);
        return bytes;
    }
    [SupportedOSPlatform("windows")]
    internal static void VerifyImmutable(string path, bool directory)
    {
        PrivatePaths.NoLinks(path);
        // Every parent must prevent ordinary users/service SID from replacing a pin.
        for (var current = path; current != null; current = Path.GetDirectoryName(current))
        {
            var isDirectory = directory || current != path;
            FileSystemSecurity acl = isDirectory ? new DirectoryInfo(current).GetAccessControl() : new FileInfo(current).GetAccessControl();
            var administrators = new HashSet<string>(StringComparer.Ordinal) { "S-1-5-18", "S-1-5-32-544" };
            if (acl.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !administrators.Contains(owner.Value)) throw new ConnectionException("execution_invalid");
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && !administrators.Contains(rule.IdentityReference.Value) && GrantsMutation(rule.FileSystemRights))
                    throw new ConnectionException("execution_invalid");
            if (Path.GetPathRoot(current) == current) break;
        }
    }
}
