using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Aegis.Connection;

internal interface IDirectoryDurability
{
    void Synchronize(string directory);
}

internal sealed class DirectoryDurability : IDirectoryDurability
{
    public void Synchronize(string directory)
    {
        if (!OperatingSystem.IsLinux()) return;
        PrivatePaths.NoLinks(directory);
        // Linux x64: read-only directory descriptor; never follow the final symlink,
        // and never leak the descriptor across exec. SafeFileHandle owns the one close.
        const int flags = 0x10000 | 0x20000 | 0x80000; // O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        int descriptor;
        do { descriptor = Open(directory, flags); } while (descriptor == -1 && Marshal.GetLastPInvokeError() == 4); // EINTR
        if (descriptor == -1) throw new IOException("directory_sync_failed");
        using var handle = new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
        FlushDirectory(handle);
    }
    internal static void FlushDirectory(SafeFileHandle descriptor)
    {
        int result;
        do { result = Fsync(descriptor); } while (result == -1 && Marshal.GetLastPInvokeError() == 4);
        if (result != 0) throw new IOException("directory_sync_failed");
    }
    internal static void Hierarchy(string directory, IDirectoryDurability durability)
    {
        // A newly created ancestor must itself be reachable durably from its parent.
        // Repeat on acquisition even for existing directories after an earlier failed sync.
        for (var current = new DirectoryInfo(directory); current != null; current = current.Parent)
            durability.Synchronize(current.FullName);
    }
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(SafeFileHandle descriptor);
}
