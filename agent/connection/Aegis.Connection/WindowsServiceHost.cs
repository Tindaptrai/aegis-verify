using System.Runtime.InteropServices;

namespace Aegis.Connection;

internal enum ServiceState : uint { Stopped = 1, StartPending = 2, StopPending = 3, Running = 4 }
internal readonly record struct ServiceStatus(ServiceState State, uint AcceptedControls = 0, uint Win32ExitCode = 0, uint ServiceExitCode = 0, uint Checkpoint = 0, uint WaitHint = 0);
internal interface IWindowsServiceApi
{
    bool Dispatch(Action serviceMain);
    bool Register(Action<uint> control);
    bool Report(ServiceStatus status);
}

public static class WindowsServiceHost
{
    public static int Run(string stateDirectory) => Run(stateDirectory, null);
    public static int Run(string stateDirectory, Execution.ExecutionConfigurationPaths? paths)
    {
        if (!OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(stateDirectory)) return 3;
        return Run(stateDirectory, new NativeServiceApi(), (directory, token) => Execution.AgentSupervisor.RunAsync(directory, paths, token));
    }
    internal static int Run(string stateDirectory, IWindowsServiceApi api, Func<string, CancellationToken, Task<int>> loop)
    {
        if (!Path.IsPathFullyQualified(stateDirectory)) return 3;
        using var lifetime = new ServiceLifetime(stateDirectory, api, loop);
        try { return api.Dispatch(lifetime.ServiceMain) ? lifetime.ExitCode : 3; }
        catch { return 3; } // No exception may escape an unmanaged service entry point.
        finally { GC.KeepAlive(api); GC.KeepAlive(lifetime); }
    }
    private sealed class ServiceLifetime(string directory, IWindowsServiceApi api, Func<string, CancellationToken, Task<int>> loop) : IDisposable
    {
        private readonly object gate = new();
        private readonly CancellationTokenSource cancellation = new();
        private readonly TaskCompletionSource stopRequested = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private ServiceStatus status = new(ServiceState.StartPending);
        private bool controlFailed;
        internal int ExitCode { get; private set; } = 3;
        internal void ServiceMain()
        {
            bool registered = false, stopWaitBounded = false;
            Task<int>? work = null;
            try
            {
                if (!api.Register(Control)) return;
                registered = true;
                Report(new(ServiceState.StartPending, Checkpoint: 1, WaitHint: 20000));
                work = loop(directory, cancellation.Token);
                if (!work.IsCompleted) Report(new(ServiceState.Running, AcceptedControls: 5));
                if (Task.WhenAny(work, stopRequested.Task).GetAwaiter().GetResult() == stopRequested.Task)
                {
                    // Leave time for STOPPED and dispatcher teardown inside the 20s contract.
                    stopWaitBounded = true;
                    ExitCode = work.WaitAsync(TimeSpan.FromSeconds(18)).GetAwaiter().GetResult();
                }
                else ExitCode = work.GetAwaiter().GetResult();
                if (controlFailed) ExitCode = 3;
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { ExitCode = controlFailed ? 3 : 0; }
            catch { ExitCode = 3; }
            finally
            {
                try { cancellation.Cancel(); } catch { ExitCode = 3; }
                if (work != null && !work.IsCompleted && !stopWaitBounded)
                {
                    try { work.WaitAsync(TimeSpan.FromSeconds(18)).GetAwaiter().GetResult(); } catch { }
                }
                if (registered)
                {
                    try { Report(new(ServiceState.Stopped, Win32ExitCode: ExitCode == 0 ? 0u : 1066u, ServiceExitCode: (uint)ExitCode)); }
                    catch { ExitCode = 3; }
                }
            }
        }
        private void Report(ServiceStatus next)
        {
            lock (gate)
            {
                status = next;
                if (!api.Report(next)) throw new ConnectionException("service_status_failed");
            }
        }
        private void Control(uint control)
        {
            try
            {
                lock (gate)
                {
                    if (control == 4) { if (!api.Report(status)) throw new ConnectionException("service_status_failed"); return; }
                    if (control is not (1 or 5) || status.State is ServiceState.Stopped or ServiceState.StopPending) return;
                    Report(new(ServiceState.StopPending, Checkpoint: 1, WaitHint: 20000));
                }
                cancellation.Cancel(); stopRequested.TrySetResult();
            }
            catch
            {
                controlFailed = true;
                try { cancellation.Cancel(); } catch { }
                stopRequested.TrySetResult();
            }
        }
        public void Dispose() => cancellation.Dispose();
    }

    private sealed class NativeServiceApi : IWindowsServiceApi
    {
        private const string Name = "AegisAgent";
        private ServiceMainCallback? mainCallback;
        private HandlerCallback? controlCallback;
        private nint statusHandle;
        public bool Dispatch(Action serviceMain)
        {
            mainCallback = (_, _) => serviceMain();
            var table = new[] { new ServiceEntry { Name = Name, Main = Marshal.GetFunctionPointerForDelegate(mainCallback) }, default };
            bool result = StartServiceCtrlDispatcherW(table);
            GC.KeepAlive(mainCallback); GC.KeepAlive(controlCallback);
            return result;
        }
        public bool Register(Action<uint> control)
        {
            controlCallback = (command, _, _, _) => { control(command); return 0; };
            statusHandle = RegisterServiceCtrlHandlerExW(Name, controlCallback, 0);
            return statusHandle != 0;
        }
        public bool Report(ServiceStatus status)
        {
            var native = new NativeStatus { ServiceType = 0x10, CurrentState = (uint)status.State, ControlsAccepted = status.AcceptedControls, Win32ExitCode = status.Win32ExitCode, ServiceSpecificExitCode = status.ServiceExitCode, CheckPoint = status.Checkpoint, WaitHint = status.WaitHint };
            return SetServiceStatus(statusHandle, ref native);
        }
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void ServiceMainCallback(uint argumentCount, nint arguments);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint HandlerCallback(uint control, uint eventType, nint eventData, nint context);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ServiceEntry { [MarshalAs(UnmanagedType.LPWStr)] public string? Name; public nint Main; }
        [StructLayout(LayoutKind.Sequential)]
        private struct NativeStatus { public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint; }
        [DllImport("advapi32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)] private static extern bool StartServiceCtrlDispatcherW([In] ServiceEntry[] table);
        [DllImport("advapi32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern nint RegisterServiceCtrlHandlerExW(string serviceName, HandlerCallback handler, nint context);
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetServiceStatus(nint statusHandle, ref NativeStatus status);
    }
}
