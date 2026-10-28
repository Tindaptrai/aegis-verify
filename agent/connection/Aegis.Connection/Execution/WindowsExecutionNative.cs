using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Aegis.Connection.Execution;

internal sealed record NativeExecutionResult(ExecutionObservation Observation, byte[] Output);

// Lifecycle containment only. The child has the same service SID as its supervisor.
internal static class WindowsExecutionNative
{
    private const int OutputLimit = 1024 * 1024;
    private static readonly SemaphoreSlim CreationGate = new(1, 1);
    // Narrow native-call boundary, internal to this assembly and its test assembly.
    internal class NativeApi
    {
        internal virtual bool Attribute(nint list, nuint attribute, nint value, nuint bytes) => UpdateProcThreadAttribute(list, 0, attribute, value, bytes, 0, 0);
        internal virtual uint Resume(nint thread) => ResumeThread(thread);
        internal virtual bool Terminate(nint job) => TerminateJobObject(job, 1);
        internal virtual bool Active(nint job, out uint count)
        {
            var ok = QueryInformationJobObject(job, 1, out var accounting, (uint)Marshal.SizeOf<BasicAccounting>(), out _);
            count = accounting.ActiveProcesses; return ok;
        }
    }

    internal static async Task<NativeExecutionResult> RunAsync(string executable, string[] arguments, string directory,
        TimeSpan timeout, Func<CancellationToken, Task> beforeCreate, Action<ExecutionCreation> observedCreated,
        CancellationToken stop, Action? finalCheck = null, Action<byte[]>? finalizeOutput = null, NativeApi? api = null)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess) throw new ConnectionException("unsupported_platform");
        if (!Path.IsPathFullyQualified(executable) || !Path.IsPathFullyQualified(directory) || timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(300)) throw new ConnectionException("execution_invalid");
        api ??= new NativeApi();
        var clock = Stopwatch.StartNew(); var budgetGate = new object(); var deadline = timeout;
        var reserve = TimeSpan.FromMilliseconds(Math.Min(5000, timeout.TotalMilliseconds / 4));
        using var admission = CancellationTokenSource.CreateLinkedTokenSource(stop);
        admission.CancelAfter(timeout - reserve);
        using var cancelled = stop.Register(() => { lock (budgetGate) { var shortened = clock.Elapsed + TimeSpan.FromSeconds(5); if (shortened < deadline) deadline = shortened; } });
        TimeSpan Remaining() { lock (budgetGate) return deadline - clock.Elapsed; }
        using var output = new MemoryStream();
        nint job = 0, read = 0, write = 0, input = 0, attributes = 0, jobArray = 0, handles = 0, environment = 0;
        ProcessInformation process = default; bool initialized = false, held = false, created = false, resumed = false;
        bool cleanup = false, eof = false, outputValid = true; DateTimeOffset? started = null; int? exit = null;
        void Drain()
        {
            if (read == 0 || eof) return;
            // Peek avoids an unbounded anonymous-pipe reader/Join during SCM STOP.
            var buffer = new byte[4096]; var batch = 0;
            while (Remaining() > TimeSpan.Zero && batch++ < 64)
            {
                if (!PeekNamedPipe(read, 0, 0, 0, out var available, 0))
                { if (Marshal.GetLastPInvokeError() == 109) { eof = true; return; } throw NativeError(); }
                if (available == 0) return;
                if (!ReadFile(read, buffer, Math.Min((uint)buffer.Length, available), out var count, 0)) throw NativeError();
                if (count == 0) return;
                var keep = Math.Min((int)count, OutputLimit - (int)output.Length);
                if (keep > 0) output.Write(buffer, 0, keep);
            }
        }
        try
        {
            await beforeCreate(admission.Token);
            stop.ThrowIfCancellationRequested();
            if (Remaining() <= reserve) throw new ConnectionException("execution_deadline");
            await CreationGate.WaitAsync(admission.Token); held = true;
            job = CreateJobObjectW(0, null); if (job == 0) throw NativeError();
            var limits = new ExtendedLimits(); limits.Basic.LimitFlags = 0x2000;
            if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>())) throw NativeError();
            var security = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Inherit = true };
            if (!CreatePipe(out read, out write, ref security, 0) || !SetHandleInformation(read, 1, 0)) throw NativeError();
            input = CreateFileW("NUL", 0x80000000, 3, ref security, 3, 0, 0); if (input == -1) throw NativeError();
            nuint size = 0;
            if (InitializeProcThreadAttributeList(0, 2, 0, ref size) || Marshal.GetLastPInvokeError() != 122 || size == 0 || size > 65536) throw NativeError();
            attributes = Marshal.AllocHGlobal((nint)size);
            if (!InitializeProcThreadAttributeList(attributes, 2, 0, ref size)) throw NativeError(); initialized = true;
            jobArray = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobArray, job);
            handles = Marshal.AllocHGlobal(IntPtr.Size * 2); Marshal.WriteIntPtr(handles, input); Marshal.WriteIntPtr(handles, IntPtr.Size, write);
            if (!api.Attribute(attributes, 0x2000D, jobArray, (nuint)IntPtr.Size) ||
                !api.Attribute(attributes, 0x20002, handles, (nuint)(IntPtr.Size * 2))) throw NativeError();
            var startup = new StartupInfoEx { Startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfoEx>(), Flags = 0x100, Input = input, Output = write, Error = write }, Attributes = attributes };
            if (Marshal.SizeOf<StartupInfo>() != 104 || Marshal.SizeOf<StartupInfoEx>() != 112) throw new ConnectionException("unsupported_platform");
            var command = new StringBuilder(Quote(executable)); foreach (var value in arguments) command.Append(' ').Append(Quote(value));
            if (command.Length >= 32767) throw new ConnectionException("execution_invalid");
            environment = Marshal.StringToHGlobalUni(ChildEnvironment());
            // No asynchronous work between this final time/cancellation check and creation.
            finalCheck?.Invoke(); admission.Token.ThrowIfCancellationRequested();
            if (Remaining() <= reserve) throw new ConnectionException("execution_deadline");
            if (!CreateProcessW(executable, command, 0, 0, true, 0x4 | 0x400 | 0x80000 | 0x08000000,
                environment, directory, ref startup, out process)) throw NativeError();
            created = true;
            if (!IsProcessInJob(process.Process, job, out var contained) || !contained ||
                !IsProcessInJob(GetCurrentProcess(), job, out var supervisorInside) || supervisorInside) throw NativeError();
            if (!GetProcessTimes(process.Process, out var creation, out _, out _, out _)) throw NativeError();
            var at = DateTimeOffset.UtcNow;
            observedCreated(new((int)process.ProcessId, creation, Environment.TickCount64, ExecutionCoordinator.Stamp(at)));
            finalCheck?.Invoke(); admission.Token.ThrowIfCancellationRequested();
            if (Remaining() <= reserve) throw new ConnectionException("execution_deadline");
            if (api.Resume(process.Thread) != 1) throw NativeError();
            started = at; resumed = true;
            Close(ref process.Thread); Close(ref write); Close(ref input);
            CreationGate.Release(); held = false;
            while (Remaining() > reserve && !stop.IsCancellationRequested)
            {
                Drain();
                var wait = WaitForSingleObject(process.Process, 0);
                if (wait == 0)
                { if (!GetExitCodeProcess(process.Process, out var code)) throw NativeError(); exit = unchecked((int)code); break; }
                if (wait != 258) throw NativeError();
                await Task.Delay(20);
            }
        }
        catch (Exception e) when (e is Win32Exception or IOException or UnauthorizedAccessException or ConnectionException or OperationCanceledException or ArgumentException)
        { exit = null; }
        finally
        {
            Close(ref write); Close(ref input);
            if (held) CreationGate.Release();
            if (initialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != 0) Marshal.FreeHGlobal(attributes);
            if (jobArray != 0) Marshal.FreeHGlobal(jobArray);
            if (handles != 0) Marshal.FreeHGlobal(handles);
            if (environment != 0) Marshal.FreeHGlobal(environment);
            try
            {
                if (job != 0 && created)
                {
                    var terminated = api.Terminate(job);
                    while (Remaining() > TimeSpan.Zero)
                    {
                        Drain();
                        if (!api.Active(job, out var active)) break;
                        if (active == 0 && eof) { cleanup = terminated; break; }
                        await Task.Delay(10);
                    }
                }
            }
            catch (Exception e) when (e is Win32Exception or IOException or ObjectDisposedException) { outputValid = false; }
            try
            {
                if (Remaining() <= TimeSpan.Zero) outputValid = false;
                else { finalizeOutput?.Invoke(output.ToArray()); if (Remaining() <= TimeSpan.Zero) outputValid = false; }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ObjectDisposedException) { outputValid = false; }
            Close(ref process.Thread); Close(ref process.Process); Close(ref job); Close(ref read);
        }
        // Closing a job is fail-safe termination, never retrospective cleanup proof.
        return new(new(resumed ? started : null, DateTimeOffset.UtcNow, exit, created && cleanup && outputValid), output.ToArray());
    }
    internal static string Quote(string value)
    {
        if (value.IndexOf('\0') >= 0) throw new ConnectionException("execution_invalid");
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (var c in value)
        {
            if (c == '\\') { slashes++; continue; }
            result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes).Append(c); slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }
    private static string ChildEnvironment()
    {
        // Explicit bounded values only; never inherit connector credentials or runtime overrides.
        var values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in new[] { "SystemRoot", "WINDIR", "COMPUTERNAME", "USERNAME", "USERDOMAIN", "TEMP", "TMP" })
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (value != null) { if (value.Length > 1024 || value.IndexOf('\0') >= 0) throw new ConnectionException("execution_invalid"); values.Add(name, value); }
        }
        values["PATH"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
        return string.Concat(values.Select(v => v.Key + "=" + v.Value + '\0')) + '\0';
    }
    private static Win32Exception NativeError() => new(Marshal.GetLastPInvokeError());
    private static void Close(ref nint value) { var handle = value; value = 0; if (handle != 0 && handle != -1) CloseHandle(handle); }
    [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { public int Length; public nint Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfo
    {
        public int Size; public nint Reserved, Desktop, Title; public int X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        public short Show, ReservedSize; public nint ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo Startup; public nint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation { public nint Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    { public long ProcessTime, JobTime; public uint LimitFlags; public nuint Minimum, Maximum; public uint ActiveLimit; public nuint Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong Read, Write, Other, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits { public BasicLimits Basic; public IoCounters Io; public nuint ProcessMemory, JobMemory, PeakProcess, PeakJob; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicAccounting
    { public long TotalUser, TotalKernel, PeriodUser, PeriodKernel; public uint Faults, TotalProcesses, ActiveProcesses, TerminatedProcesses; }
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)] private static extern nint CreateJobObjectW(nint security, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(nint job, int kind, ref ExtendedLimits info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreatePipe(out nint read, out nint write, ref SecurityAttributes security, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetHandleInformation(nint handle, uint mask, uint flags);
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)] private static extern nint CreateFileW(string path, uint access, uint share, ref SecurityAttributes security, uint creation, uint flags, nint template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool InitializeProcThreadAttributeList(nint list, int count, uint flags, ref nuint bytes);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool UpdateProcThreadAttribute(nint list, uint flags, nuint attribute, nint value, nuint bytes, nint previous, nint returned);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(nint list);
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(string application, StringBuilder command, nint processSecurity, nint threadSecurity, [MarshalAs(UnmanagedType.Bool)] bool inherit,
        uint flags, nint environment, string directory, ref StartupInfoEx startup, out ProcessInformation process);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsProcessInJob(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);
    [DllImport("kernel32.dll")] private static extern nint GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetProcessTimes(nint process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(nint thread);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(nint handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(nint process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateJobObject(nint job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool QueryInformationJobObject(nint job, int kind, out BasicAccounting info, uint bytes, out uint returned);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool PeekNamedPipe(nint pipe, nint buffer, uint size, nint read, out uint available, nint left);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ReadFile(nint file, byte[] buffer, uint count, out uint read, nint overlapped);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(nint handle);
}
