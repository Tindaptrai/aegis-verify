using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;

namespace Aegis.Connection;

internal static class PrivatePaths
{
    internal static void NoLinks(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path)); current != null; current = current.Parent)
            if (current.Exists && current.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new ConnectionException("state_invalid");
        if (File.Exists(path) && File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint)) throw new ConnectionException("state_invalid");
    }
    internal static void CreateDirectory(string path)
    {
        NoLinks(path);
        if (!Directory.Exists(path))
        {
            if (OperatingSystem.IsWindows()) new DirectoryInfo(path).Create(DirectoryAcl());
            else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        Verify(path, true);
    }
    internal static FileStream CreateFile(string path)
    {
        NoLinks(path);
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.WriteThrough };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        var stream = new FileStream(path, options);
        try { if (OperatingSystem.IsWindows()) new FileInfo(path).SetAccessControl(FileAcl()); return stream; }
        catch { stream.Dispose(); throw; }
    }
    internal static void Verify(string path, bool directory)
    {
        NoLinks(path);
        if (OperatingSystem.IsWindows()) VerifyWindows(path, directory);
        else
        {
            var mode = File.GetUnixFileMode(path);
            var expected = directory ? UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute : UnixFileMode.UserRead | UnixFileMode.UserWrite;
            if (mode != expected) throw new ConnectionException("state_invalid");
        }
    }
    [SupportedOSPlatform("windows")]
    private static HashSet<string> Allowed()
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal) { WindowsIdentity.GetCurrent().User!.Value, "S-1-5-18", "S-1-5-32-544" };
        try { allowed.Add(((SecurityIdentifier)new NTAccount("NT SERVICE", "AegisAgent").Translate(typeof(SecurityIdentifier))).Value); } catch (IdentityNotMappedException) { }
        return allowed;
    }
    [SupportedOSPlatform("windows")]
    private static DirectorySecurity DirectoryAcl()
    {
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
        foreach (var sid in Allowed()) acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return acl;
    }
    [SupportedOSPlatform("windows")]
    private static FileSecurity FileAcl()
    {
        var acl = new FileSecurity(); acl.SetAccessRuleProtection(true, false);
        foreach (var sid in Allowed()) acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl, AccessControlType.Allow));
        return acl;
    }
    [SupportedOSPlatform("windows")]
    private static void VerifyWindows(string path, bool directory)
    {
        FileSystemSecurity acl = directory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
        var allowed = Allowed();
        if (acl.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !allowed.Contains(owner.Value)) throw new ConnectionException("state_invalid");
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !allowed.Contains(rule.IdentityReference.Value)) throw new ConnectionException("state_invalid");
    }
}
