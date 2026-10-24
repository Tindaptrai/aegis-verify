using System.Diagnostics;
using Aegis.Connection;

internal static partial class Program
{
    private static void ServiceHostTests()
    {
        foreach (uint control in new uint[] { 1, 5 })
            Test($"SCM control {control} cancels outstanding work with orderly stopped status", () =>
            {
                using var temp = new Scratch();
                bool entered = false, cancelled = false;
                var api = new ServiceBoundary { OnRunning = boundary => boundary.Control!(control) };
                var watch = Stopwatch.StartNew();
                int result = WindowsServiceHost.Run(temp.Path, api, async (path, token) =>
                {
                    Check(path == temp.Path, "wrong persistent state path"); entered = true;
                    try { await Task.Delay(Timeout.Infinite, token); }
                    catch (OperationCanceledException) when (token.IsCancellationRequested) { cancelled = true; }
                    return 0;
                });
                Check(result == 0 && entered && cancelled && watch.Elapsed < TimeSpan.FromSeconds(2), "service did not cancel pending work");
                Check(api.Statuses.Select(s => s.State).SequenceEqual(new[] { ServiceState.StartPending, ServiceState.Running, ServiceState.StopPending, ServiceState.Stopped }), "incorrect SCM lifecycle");
                Check(api.Statuses[0].AcceptedControls == 0 && api.Statuses[0].WaitHint <= 20000 && api.Statuses[0].Checkpoint > 0, "invalid startup status");
                Check(api.Statuses[1].AcceptedControls == 5 && api.Statuses[2].AcceptedControls == 0 && api.Statuses[2].WaitHint <= 20000, "invalid control acceptance or stop deadline");
                Check(api.Statuses[^1].Win32ExitCode == 0 && api.Statuses[^1].ServiceExitCode == 0, "requested stop reported failure");
            });
        Test("SCM terminal identity startup failure is failed stopped without running", () =>
        {
            using var temp = new Scratch(); var api = new ServiceBoundary();
            int result = WindowsServiceHost.Run(temp.Path, api, (_, _) => Task.FromResult(3));
            Check(result == 3 && api.Statuses.Select(s => s.State).SequenceEqual(new[] { ServiceState.StartPending, ServiceState.Stopped }), "startup failure advertised running");
            Check(api.Statuses[^1].Win32ExitCode == 1066 && api.Statuses[^1].ServiceExitCode == 3, "SCM did not receive real failed status");
        });
        Test("SCM dispatcher and registration failure never start heartbeat", () =>
        {
            using var temp = new Scratch(); int calls = 0;
            foreach (var api in new[] { new ServiceBoundary { DispatchSucceeds = false }, new ServiceBoundary { RegisterSucceeds = false } })
            {
                int result = WindowsServiceHost.Run(temp.Path, api, (_, _) => { calls++; return Task.FromResult(0); });
                Check(result == 3 && calls == 0 && api.Statuses.Count == 0 && api.DispatchCalls == 1, "unregistered service started work or pretended dispatcher success");
            }
        });
        Test("SCM worker exception and running failure report service error", () =>
        {
            using var temp = new Scratch();
            var api = new ServiceBoundary();
            int result = WindowsServiceHost.Run(temp.Path, api, (_, _) => throw new IOException("synthetic startup exception"));
            Check(result == 3 && api.Statuses.Count > 0 && api.Statuses[^1].State == ServiceState.Stopped && api.Statuses[^1].Win32ExitCode == 1066, "startup exception escaped SCM boundary");
            var complete = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            api = new ServiceBoundary { OnRunning = _ => complete.SetResult(3) };
            result = WindowsServiceHost.Run(temp.Path, api, (_, _) => complete.Task);
            Check(result == 3 && api.Statuses.Any(s => s.State == ServiceState.Running) && api.Statuses[^1].ServiceExitCode == 3, "running failure lost service error");
        });
        Test("SCM interrogate reports current status and status failure cancels work", () =>
        {
            using var temp = new Scratch();
            var api = new ServiceBoundary { OnRunning = boundary => { boundary.Control!(4); boundary.Control!(1); } };
            int result = WindowsServiceHost.Run(temp.Path, api, async (_, token) => { await Task.Delay(Timeout.Infinite, token); return 0; });
            Check(result == 0 && api.Statuses.Count(s => s.State == ServiceState.Running) == 2, "interrogate changed or failed to report current status");
            bool cancelled = false;
            api = new ServiceBoundary { RejectRunningStatus = true };
            result = WindowsServiceHost.Run(temp.Path, api, async (_, token) => { try { await Task.Delay(Timeout.Infinite, token); } catch (OperationCanceledException) { cancelled = true; } return 0; });
            Check(result == 3 && cancelled && api.Statuses[^1].State == ServiceState.Stopped, "status failure left heartbeat running");
        });
        Test("SCM real dispatcher outside service refuses without creating state or prompting", async () =>
        {
            using var temp = new Scratch();
            int prompts = 0;
            int result = await Aegis.Connection.Program.RunAsync(["service", "--state-dir", temp.Path], () => { prompts++; return new string('a', 64); }, CancellationToken.None);
            Check(result == 3 && prompts == 0 && !Directory.Exists(temp.Path), "service command outside SCM created identity or accepted console lifetime");
            result = await Aegis.Connection.Program.RunAsync(["service", "--state-dir", temp.Path, "--manager", "https://manager.invalid"], () => throw new Exception("unexpected prompt"), CancellationToken.None);
            Check(result == 2, "service accepted connect configuration");
        });
    }
    // SCM itself is external and forbidden on the desktop. This boundary dispatches
    // our actual lifecycle and observes emitted native statuses/control effects.
    private sealed class ServiceBoundary : IWindowsServiceApi
    {
        public bool DispatchSucceeds { get; init; } = true;
        public bool RegisterSucceeds { get; init; } = true;
        public bool RejectRunningStatus { get; init; }
        public Action<ServiceBoundary>? OnRunning { get; init; }
        public Action<uint>? Control { get; private set; }
        public List<ServiceStatus> Statuses { get; } = [];
        public int DispatchCalls { get; private set; }
        private bool runningHandled;
        public bool Dispatch(Action main) { DispatchCalls++; if (!DispatchSucceeds) return false; main(); return true; }
        public bool Register(Action<uint> control) { Control = control; return RegisterSucceeds; }
        public bool Report(ServiceStatus status)
        {
            Statuses.Add(status);
            if (status.State == ServiceState.Running && !runningHandled) { runningHandled = true; OnRunning?.Invoke(this); }
            return !(RejectRunningStatus && status.State == ServiceState.Running);
        }
    }
}
