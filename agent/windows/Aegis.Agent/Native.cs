#nullable disable
using System.Collections;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace Aegis.Agent;

internal sealed class OwnedJob : IDisposable
{
    private IntPtr handle;
    public OwnedJob()
    {
        handle = Native.CreateJobObject(IntPtr.Zero, null);
        if (handle == IntPtr.Zero) throw new Win32Exception();
        Native.ExtendedLimits limits = new Native.ExtendedLimits();
        limits.BasicLimitInformation.LimitFlags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (!Native.SetInformationJobObject(handle, 9, ref limits, Marshal.SizeOf(limits)))
        {
            int code = Marshal.GetLastWin32Error();
            Dispose();
            throw new Win32Exception(code, "Could not configure owned-process cleanup.");
        }
    }

    public bool TerminateAndWait()
    {
        if (!Native.TerminateJobObject(handle, 1)) return false;
        var until = System.Diagnostics.Stopwatch.StartNew();
        while (until.ElapsedMilliseconds < 5000) { if (ProcessIds().Length == 0) return true; Thread.Sleep(25); }
        return false;
    }
    public void Assign(IntPtr process)
    {
        if (!Native.AssignProcessToJobObject(handle, process))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not contain the AEGIS process. Startup was stopped.");
    }

    public int[] ProcessIds()
    {
        if (handle == IntPtr.Zero) return new int[0];
        const int capacity = 256;
        int size = 8 + capacity * IntPtr.Size;
        IntPtr memory = Marshal.AllocHGlobal(size);
        try
        {
            int returned;
            if (!Native.QueryInformationJobObject(handle, 3, memory, size, out returned)) throw new Win32Exception();
            int count = Math.Min(Marshal.ReadInt32(memory, 4), capacity);
            int[] pids = new int[count];
            for (int i = 0; i < count; i++) pids[i] = Marshal.ReadIntPtr(memory, 8 + i * IntPtr.Size).ToInt32();
            return pids;
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    public void Dispose()
    {
        IntPtr previous = Interlocked.Exchange(ref handle, IntPtr.Zero);
        if (previous != IntPtr.Zero) Native.CloseHandle(previous);
    }
}

internal sealed class NativeChild : IDisposable
{
    private IntPtr process;
    private readonly Thread reader;
    public readonly int Id;
    private NativeChild(IntPtr process, int id, Stream stream, Action<string> output)
    {
        this.process = process;
        Id = id;
        reader = new Thread(delegate ()
        {
            try
            {
                using (StreamReader lines = new StreamReader(stream, Encoding.UTF8, true))
                {

                    char[] buffer = new char[4096]; int count; while ((count = lines.Read(buffer, 0, buffer.Length)) > 0) output(new string(buffer, 0, count));
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
        });
        reader.IsBackground = true;
        reader.Start();
    }

    public static NativeChild Start(OwnedJob job, string executable, string[] args, Action<string> output, string directory)
    {
        Native.SecurityAttributes security = new Native.SecurityAttributes();
        security.Length = Marshal.SizeOf(security);
        security.InheritHandle = true;
        IntPtr read = IntPtr.Zero, write = IntPtr.Zero, input = IntPtr.Zero;
        Native.ProcessInformation information = new Native.ProcessInformation();
        try
        {
            if (!Native.CreatePipe(out read, out write, ref security, 0)
                || !Native.SetHandleInformation(read, 1, 0)) throw new Win32Exception();
            input = Native.CreateFile("NUL", 0x80000000, 3, ref security, 3, 0, IntPtr.Zero);
            if (input == new IntPtr(-1)) throw new Win32Exception();
            Native.StartupInfo startup = new Native.StartupInfo();
            startup.Size = Marshal.SizeOf(startup);
            startup.Flags = 0x100; // STARTF_USESTDHANDLES
            startup.StandardInput = input;
            startup.StandardOutput = write;
            startup.StandardError = write;
            StringBuilder command = new StringBuilder(Quote(executable));
            foreach (string arg in args) command.Append(' ').Append(Quote(arg));
            // These affect Python only when honored by the existing runtime; no engine bytes change.
            string environment = ChildEnvironment();
            IntPtr environmentBlock = Marshal.StringToHGlobalUni(environment);
            try
            {
                if (!Native.CreateProcess(executable, command, IntPtr.Zero, IntPtr.Zero, true,
                    0x00000004 | 0x08000000 | 0x00000400, environmentBlock, directory,
                    ref startup, out information)) throw new Win32Exception();
            }
            finally { Marshal.FreeHGlobal(environmentBlock); }
            job.Assign(information.Process);
            if (Native.ResumeThread(information.Thread) == UInt32.MaxValue) throw new Win32Exception();
            Native.CloseHandle(information.Thread);
            information.Thread = IntPtr.Zero;
            Native.CloseHandle(write);
            write = IntPtr.Zero;
            SafeFileHandle pipe = new SafeFileHandle(read, true);
            read = IntPtr.Zero;
            NativeChild child = new NativeChild(information.Process, (int)information.ProcessId,
                new FileStream(pipe, FileAccess.Read, 4096, false), output);
            information.Process = IntPtr.Zero;
            return child;
        }
        finally
        {
            if (information.Process != IntPtr.Zero)
            {
                Native.TerminateProcess(information.Process, 1);
                Native.WaitForSingleObject(information.Process, 5000);
                Native.CloseHandle(information.Process);
            }
            if (information.Thread != IntPtr.Zero) Native.CloseHandle(information.Thread);
            if (read != IntPtr.Zero) Native.CloseHandle(read);
            if (write != IntPtr.Zero) Native.CloseHandle(write);
            if (input != IntPtr.Zero && input != new IntPtr(-1)) Native.CloseHandle(input);
        }
    }

    private static string ChildEnvironment()
    {
        SortedDictionary<string, string> values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables()) values[(string)entry.Key] = (string)entry.Value;
        values["PYTHONUNBUFFERED"] = "1";
        values["PYTHONIOENCODING"] = "utf-8";
        values["PYTHONUTF8"] = "1";
        StringBuilder block = new StringBuilder();
        foreach (KeyValuePair<string, string> entry in values) block.Append(entry.Key).Append('=').Append(entry.Value).Append('\0');
        return block.Append('\0').ToString();
    }

    // Windows CommandLineToArgv/CRT escaping; arguments never pass through a shell.
    private static string Quote(string value)
    {
        StringBuilder result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char character in value)
        {
            if (character == '\\') { slashes++; continue; }
            if (character == '"') result.Append('\\', slashes * 2 + 1).Append(character);
            else result.Append('\\', slashes).Append(character);
            slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }

    public bool HasExited { get { return process == IntPtr.Zero || Native.WaitForSingleObject(process, 0) == 0; } }
    public int ExitCode
    {
        get
        {
            uint code;
            if (!Native.GetExitCodeProcess(process, out code)) throw new Win32Exception();
            return (int)code;
        }
    }
    public void DrainOutput() { reader.Join(2000); }
    public void Dispose()
    {
        IntPtr previous = Interlocked.Exchange(ref process, IntPtr.Zero);
        if (previous == IntPtr.Zero) return;
        Native.WaitForSingleObject(previous, 5000);
        Native.CloseHandle(previous);
        reader.Join(2000);
    }
}

internal static class Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityAttributes { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct StartupInfo
    {
        public int Size; public string Reserved, Desktop, Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public short ShowWindow, ReservedSize; public IntPtr ReservedBytes, StandardInput, StandardOutput, StandardError;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessInformation { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct BasicLimits
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtendedLimits
    {
        public BasicLimits BasicLimitInformation; public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetInformationJobObject(IntPtr job, int info, ref ExtendedLimits limits, int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryInformationJobObject(IntPtr job, int info, IntPtr data, int size, out int returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SecurityAttributes attributes, int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetHandleInformation(IntPtr handle, int mask, int flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr CreateFile(string name, uint access, uint share, ref SecurityAttributes attributes, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, IntPtr environment, string directory, ref StartupInfo startup, out ProcessInformation information);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateJobObject(IntPtr job, uint code);
}
