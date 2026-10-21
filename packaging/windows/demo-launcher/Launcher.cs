// Windows .NET Framework helper. The neighboring AEGIS 0.4.0 engine is unchanged.
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;

[assembly: AssemblyTitle("AEGIS Verify Demo Launcher")]
[assembly: AssemblyDescription("Windows helper for the unchanged AEGIS Verify 0.4.0 offline demo")]
[assembly: AssemblyProduct("AEGIS Verify Demo Launcher")]
[assembly: AssemblyCompany("AEGIS Verify")]
[assembly: AssemblyVersion("0.4.0.1")]
[assembly: AssemblyFileVersion("0.4.0.1")]

namespace AegisDemo
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length != 0 && args[0] == "--self-test")
                return SelfTest(args);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            if (args.Length != 0)
            {
                MessageBox.Show("Double-click AEGIS Verify Demo.exe to start the offline demo.",
                    "AEGIS Verify Demo", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return 1;
            }
            Application.Run(new LauncherWindow());
            return 0;
        }

        // The same lifecycle runs without a window or browser for integration checks.
        // A stop file also lets tests close the launcher while startup is in progress.
        private static int SelfTest(string[] args)
        {
            if (args.Length != 3 && (args.Length != 5 || args[3] != "--data-parent")) return 2;
            string result = Path.GetFullPath(args[1]);
            string stop = Path.GetFullPath(args[2]);
            try
            {
                using (LauncherSession session = new LauncherSession(true, args.Length == 5 ? args[4] : null))
                {
                    Thread worker = new Thread(session.Start);
                    worker.IsBackground = true;
                    worker.Start();
                    while (true)
                    {
                        session.CheckDashboard();
                        if (File.Exists(stop))
                        {
                            session.Stop();
                            worker.Join(5000);
                            WriteResult(result, session.Snapshot());
                            return 0;
                        }
                        IDictionary<string, object> status = session.Snapshot();
                        WriteResult(result, status);
                        if ((string)status["phase"] == "error")
                        {
                            worker.Join(5000);
                            return 1;
                        }
                        Thread.Sleep(150);
                    }
                }
            }
            catch (Exception error)
            {
                WriteResult(result, new Dictionary<string, object> {
                    { "phase", "error" }, { "error", error.Message }, { "browser_opened", false }
                });
                return 1;
            }
        }

        private static void WriteResult(string path, object value)
        {
            string temporary = path + ".tmp";
            File.WriteAllText(temporary, new JavaScriptSerializer().Serialize(value), new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(temporary, path, null);
            else File.Move(temporary, path);
        }
    }

    internal sealed class LauncherSession : IDisposable
    {
        private readonly object gate = new object();
        private readonly bool selfTest;
        private readonly StreamWriter log;
        private readonly StringBuilder tail = new StringBuilder();
        private readonly List<NativeChild> children = new List<NativeChild>();
        private readonly HashSet<int> childPids = new HashSet<int>();
        private readonly OwnedJob job;
        private NativeChild dashboard;
        private bool stopped, disposed, browserOpened;
        private string phase = "preparing", message = "Preparing the offline demo...", error;
        private Uri dashboardUrl;
        private readonly string sessionPath, dataPath, logPath;

        public LauncherSession(bool selfTest, string dataParent)
        {
            this.selfTest = selfTest;
            string parent;
            if (dataParent == null)
            {
                parent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AEGIS Verify", "Demo");
                Directory.CreateDirectory(parent);
            }
            else
            {
                parent = Path.GetFullPath(dataParent);
                if (!Directory.Exists(parent)) throw new IOException("The test data parent must already exist.");
            }
            sessionPath = Path.Combine(parent, "session-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(sessionPath);
            dataPath = Path.Combine(sessionPath, "demo"); // The engine requires a new target with an existing parent.
            logPath = Path.Combine(sessionPath, "launcher.log");
            log = new StreamWriter(logPath, false, new UTF8Encoding(false));
            log.AutoFlush = true;
            try { job = new OwnedJob(); }
            catch { log.Dispose(); throw; }
            Append("AEGIS Verify Demo Launcher 0.4.0.1; offline replay through neighboring aegis.exe.");
            Append("Data: " + dataPath);
        }

        public void Start()
        {
            try
            {
                string executable = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "aegis.exe");
                if (!File.Exists(executable))
                    throw new FileNotFoundException("aegis.exe is missing. Keep it beside AEGIS Verify Demo.exe.");
                NativeChild demo = StartChild(executable, new string[] { "demo", "--out", dataPath }, false);
                WaitForDemo(demo);
                SetState("starting", "Starting the dashboard...");
                dashboard = StartChild(executable,
                    new string[] { "dashboard", "--bundled", "--reports", Path.Combine(dataPath, "reports"), "--port", "0" }, true);
                DateTime deadline = DateTime.UtcNow.AddSeconds(60);
                while (DateTime.UtcNow < deadline)
                {
                    ThrowIfStopped();
                    if (dashboard.HasExited) throw new IOException("The dashboard exited before it was ready. See the log below.");
                    Uri candidate;
                    lock (gate) candidate = dashboardUrl;
                    if (candidate != null && IsReady(candidate))
                    {
                        SetState("ready", "Running: 12 reports and 6 scenarios. Close this window to stop the dashboard.");
                        if (!selfTest) OpenDashboard();
                        return;
                    }
                    Thread.Sleep(150);
                }
                throw new TimeoutException("The dashboard did not become ready within 60 seconds. See the log below.");
            }
            catch (OperationCanceledException) { }
            catch (Exception failure) { Fail(failure.Message); }
        }

        private NativeChild StartChild(string executable, string[] args, bool readAnnouncement)
        {
            lock (gate)
            {
                ThrowIfStopped();
                NativeChild child = NativeChild.Start(job, executable, args, delegate(string line) {
                    Append(line);
                    Uri candidate;
                    if (readAnnouncement && TryDashboardUrl(line, out candidate))
                        lock (gate) dashboardUrl = candidate;
                });
                children.Add(child);
                childPids.Add(child.Id);
                return child;
            }
        }

        private void WaitForDemo(NativeChild demo)
        {
            DateTime deadline = DateTime.UtcNow.AddSeconds(90);
            while (!demo.HasExited)
            {
                ThrowIfStopped();
                if (DateTime.UtcNow >= deadline) throw new TimeoutException("Demo preparation took longer than 90 seconds.");
                Thread.Sleep(100);
            }
            if (demo.ExitCode != 0) throw new IOException("AEGIS demo preparation failed (exit " + demo.ExitCode + "). See the log below.");
            demo.DrainOutput();
        }

        public static bool TryDashboardUrl(string line, out Uri uri)
        {
            uri = null;
            const string prefix = "dashboard: ";
            if (!line.StartsWith(prefix, StringComparison.Ordinal)) return false;
            int end = line.IndexOf(' ', prefix.Length);
            string value = end < 0 ? line.Substring(prefix.Length) : line.Substring(prefix.Length, end - prefix.Length);
            Uri candidate;
            if (!Uri.TryCreate(value, UriKind.Absolute, out candidate) || candidate.Scheme != Uri.UriSchemeHttp
                || !candidate.IsLoopback || candidate.Port <= 0 || candidate.AbsolutePath != "/"
                || candidate.UserInfo.Length != 0 || candidate.Query.Length != 0 || candidate.Fragment.Length != 0)
                return false;
            uri = candidate;
            return true;
        }

        private bool IsReady(Uri uri)
        {
            try
            {
                string reports = ReadHttp(new Uri(uri, "api/reports"));
                string scenarios = ReadHttp(new Uri(uri, "api/scenarios"));
                return ReadyIndexes(reports, scenarios) && ReadHttp(uri).IndexOf("AEGIS", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            catch (WebException) { return false; }
            catch (IOException) { return false; }
        }

        private static string ReadHttp(Uri uri)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.Proxy = null;
            request.AllowAutoRedirect = false;
            request.Timeout = 1500;
            request.ReadWriteTimeout = 1500;
            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                if (response.StatusCode != HttpStatusCode.OK) throw new IOException("Dashboard response was not ready.");
                using (Stream stream = response.GetResponseStream())
                using (MemoryStream bytes = new MemoryStream())
                {
                    byte[] buffer = new byte[8192];
                    int count;
                    while ((count = stream.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        if (bytes.Length + count > 1024 * 1024) throw new IOException("Dashboard response exceeded the readiness limit.");
                        bytes.Write(buffer, 0, count);
                    }
                    return Encoding.UTF8.GetString(bytes.ToArray());
                }
            }
        }

        public static bool ReadyIndexes(string reportsJson, string scenariosJson)
        {
            try
            {
                JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 1024 * 1024, RecursionLimit = 64 };
                IDictionary<string, object> reports = json.DeserializeObject(reportsJson) as IDictionary<string, object>;
                IDictionary<string, object> scenarios = json.DeserializeObject(scenariosJson) as IDictionary<string, object>;
                if (reports == null || scenarios == null || !Equals(Get(reports, "kind"), "report_index")
                    || !Equals(Get(scenarios, "kind"), "scenario_index")) return false;
                object[] entries = Get(reports, "reports") as object[];
                object[] rows = Get(scenarios, "scenarios") as object[];
                IDictionary<string, object> registry = Get(scenarios, "registry") as IDictionary<string, object>;
                if (entries == null || entries.Length != 12 || rows == null || rows.Length != 6 || registry == null
                    || !Equals(Get(registry, "configured"), true) || !Equals(Get(registry, "manifest_count"), 6)
                    || !registry.ContainsKey("error") || Get(registry, "error") != null) return false;
                object[] errors = Get(registry, "errors") as object[];
                if (errors == null || errors.Length != 0) return false;
                HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
                foreach (object item in entries)
                {
                    IDictionary<string, object> entry = item as IDictionary<string, object>;
                    if (entry == null || !entry.ContainsKey("error") || Get(entry, "error") != null
                        || !(Equals(Get(entry, "kind"), "evaluation") || Equals(Get(entry, "kind"), "comparison"))) return false;
                    string name = Get(entry, "name") as string;
                    if (String.IsNullOrEmpty(name) || !names.Add(name)) return false;
                }
                return true;
            }
            catch (ArgumentException) { return false; }
            catch (InvalidOperationException) { return false; }
        }

        private static object Get(IDictionary<string, object> values, string key)
        {
            object value;
            return values.TryGetValue(key, out value) ? value : null;
        }

        public void OpenDashboard()
        {
            Uri uri;
            lock (gate)
            {
                if (stopped || phase != "ready" || selfTest) return;
                uri = dashboardUrl;
            }
            try
            {
                // The launcher itself is outside the AEGIS job, so the user's browser stays independent.
                Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
                lock (gate) browserOpened = true;
            }
            catch (Exception failure)
            {
                Append("Could not open the default browser: " + failure.Message);
                lock (gate) message = "Dashboard is ready. Open the displayed URL in your browser, or retry Open Dashboard.";
            }
        }

        public void CheckDashboard()
        {
            NativeChild current;
            lock (gate) current = !stopped && phase == "ready" ? dashboard : null;
            if (current != null && current.HasExited) Fail("The dashboard stopped unexpectedly. See the log below.");
        }

        private void ThrowIfStopped()
        {
            if (stopped) throw new OperationCanceledException();
        }

        private void SetState(string next, string text)
        {
            lock (gate)
            {
                ThrowIfStopped();
                phase = next;
                message = text;
                Append(text);
            }
        }

        private void Append(string line)
        {
            lock (gate)
            {
                if (disposed) return;
                log.WriteLine(line);
                tail.AppendLine(line);
                if (tail.Length > 32000) tail.Remove(0, tail.Length - 24000);
            }
        }

        private void Fail(string reason)
        {
            lock (gate)
            {
                if (stopped) return;
                error = reason;
                message = reason;
                phase = "error";
                Append("ERROR: " + reason);
                StopOwned();
            }
        }

        private void RememberPids()
        {
            foreach (int pid in job.ProcessIds()) childPids.Add(pid);
        }

        private void StopOwned()
        {
            RememberPids();
            stopped = true;
            job.Dispose(); // KILL_ON_JOB_CLOSE also covers onefile bootloader descendants.
        }

        public void Stop()
        {
            lock (gate)
            {
                if (stopped) return;
                StopOwned();
                phase = "stopped";
                message = "Dashboard stopped. Demo data and log were kept.";
                Append(message);
            }
        }

        public IDictionary<string, object> Snapshot()
        {
            lock (gate)
            {
                if (!stopped) RememberPids();
                int[] pids = new int[childPids.Count];
                childPids.CopyTo(pids);
                return new Dictionary<string, object> {
                    { "phase", phase }, { "message", message }, { "error", error },
                    { "session", sessionPath }, { "data", dataPath }, { "log", logPath },
                    { "url", dashboardUrl == null ? null : dashboardUrl.AbsoluteUri },
                    { "report_count", phase == "ready" ? 12 : 0 }, { "scenario_count", phase == "ready" ? 6 : 0 },
                    { "child_pids", pids }, { "browser_opened", browserOpened }, { "log_tail", tail.ToString() }
                };
            }
        }

        public void Dispose()
        {
            Stop();
            foreach (NativeChild child in children) child.Dispose();
            lock (gate)
            {
                if (disposed) return;
                disposed = true;
                log.Dispose();
            }
        }
    }

    internal sealed class LauncherWindow : Form
    {
        private readonly Label status = new Label();
        private readonly TextBox locations = new TextBox();
        private readonly TextBox output = new TextBox();
        private readonly Button open = new Button();
        private readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        private LauncherSession session;

        public LauncherWindow()
        {
            Text = "AEGIS Verify - Offline Demo";
            ClientSize = new Size(740, 500);
            MinimumSize = Size;
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 10F);
            try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch (ArgumentException) { }
            Label title = new Label { Text = "AEGIS Verify", Font = new Font("Segoe UI", 20F, FontStyle.Bold),
                Location = new Point(22, 16), AutoSize = true };
            status.SetBounds(24, 68, 690, 52);
            status.Text = "Preparing the offline demo...";
            locations.SetBounds(24, 122, 690, 84);
            locations.Multiline = true;
            locations.ReadOnly = true;
            locations.WordWrap = false;
            locations.BorderStyle = BorderStyle.None;
            locations.BackColor = BackColor;
            locations.ScrollBars = ScrollBars.Horizontal;
            locations.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            output.SetBounds(24, 218, 690, 214);
            output.Multiline = true;
            output.ReadOnly = true;
            output.ScrollBars = ScrollBars.Both;
            output.WordWrap = false;
            output.Font = new Font("Consolas", 9F);
            output.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            open.Text = "Open Dashboard";
            open.SetBounds(24, 448, 170, 32);
            open.Enabled = false;
            open.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            open.Click += delegate { if (session != null) session.OpenDashboard(); };
            Button close = new Button { Text = "Stop and close" };
            close.SetBounds(550, 448, 164, 32);
            close.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            close.Click += delegate { Close(); };
            Controls.AddRange(new Control[] { title, status, locations, output, open, close });
            Shown += delegate {
                try
                {
                    session = new LauncherSession(false, null);
                    Thread worker = new Thread(session.Start);
                    worker.IsBackground = true;
                    worker.Start();
                    timer.Interval = 250;
                    timer.Tick += delegate { RefreshState(); };
                    timer.Start();
                }
                catch (Exception failure) { status.Text = "Could not start the demo: " + failure.Message; }
            };
            FormClosing += delegate { timer.Stop(); if (session != null) session.Stop(); };
            FormClosed += delegate { timer.Dispose(); if (session != null) session.Dispose(); };
        }

        private void RefreshState()
        {
            session.CheckDashboard();
            IDictionary<string, object> state = session.Snapshot();
            status.Text = (string)state["message"];
            status.ForeColor = (string)state["phase"] == "error" ? Color.Firebrick : SystemColors.ControlText;
            locations.Text = "Dashboard: " + (state["url"] ?? "waiting for startup") + Environment.NewLine
                + "Demo data: " + state["data"] + Environment.NewLine + "Log: " + state["log"];
            string text = (string)state["log_tail"];
            if (output.Text != text)
            {
                output.Text = text;
                output.SelectionStart = output.TextLength;
                output.ScrollToCaret();
            }
            open.Enabled = (string)state["phase"] == "ready";
        }
    }

    // Assign each suspended engine to a private job before it can spawn a child.
    // Closing the only job handle kills that tree even if the launcher is force-closed.
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
                if (!Native.QueryInformationJobObject(handle, 3, memory, size, out returned)) return new int[0];
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
            reader = new Thread(delegate() {
                try
                {
                    using (StreamReader lines = new StreamReader(stream, Encoding.UTF8, true))
                    {
                        string line;
                        while ((line = lines.ReadLine()) != null) output(line);
                    }
                }
                catch (IOException) { }
                catch (ObjectDisposedException) { }
            });
            reader.IsBackground = true;
            reader.Start();
        }

        public static NativeChild Start(OwnedJob job, string executable, string[] args, Action<string> output)
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
                        0x00000004 | 0x08000000 | 0x00000400, environmentBlock, AppDomain.CurrentDomain.BaseDirectory,
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
    }
}
