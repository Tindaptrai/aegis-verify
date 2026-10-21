"""Stdlib-only Windows launcher tests; real release tests are explicitly opted in.

Run everywhere: python packaging/windows/demo-launcher/test_launcher.py
On Windows, set AEGIS_DEMO_TEST_EXE to an existing 0.4.0 onefile aegis.exe
to also exercise real demo preparation, readiness and owned-process cleanup.
No browser or visible launcher window is opened by these tests.
"""

import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener


SOURCE = Path(__file__).with_name("Launcher.cs")
WINDOWS = sys.platform == "win32"
CSC = Path(os.environ.get("WINDIR", "C:/Windows")) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
REAL_EXE = os.environ.get("AEGIS_DEMO_TEST_EXE")
HTTP = build_opener(ProxyHandler({}))


def compile_launcher(destination, extra_source=None):
    command = [str(CSC), "/nologo", "/warnaserror+", "/target:winexe",
               "/reference:System.Windows.Forms.dll,System.Drawing.dll,System.Web.Extensions.dll",
               "/out:" + str(destination), str(SOURCE)]
    if extra_source is not None:
        command += ["/main:LauncherContracts", str(extra_source)]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if completed.returncode:
        raise AssertionError("Launcher must compile before its behavior can run:\n" + completed.stdout + completed.stderr)


def wait_status(path, phase, process, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            pass
        if last and last.get("phase") == phase:
            return last
        if process.poll() is not None:
            raise AssertionError("Launcher exited before " + phase + ": " + repr(last))
        time.sleep(0.1)
    raise AssertionError("Timed out waiting for " + phase + ": " + repr(last))


def process_alive(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
    if not handle:
        return False
    try:
        return kernel.WaitForSingleObject(handle, 0) == 258
    finally:
        kernel.CloseHandle(handle)


def stop_process(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=10)


def eventually_stopped(test, url, pids):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            HTTP.open(url, timeout=0.5).close()
            serving = True
        except (OSError, URLError):
            serving = False
        if not serving and not any(process_alive(pid) for pid in pids):
            return
        time.sleep(0.1)
    test.fail("Launcher-owned dashboard or process survived cleanup")


class LauncherBuild:
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="AEGIS launcher thử nghiệm ")
        cls.root = Path(cls.temporary.name)
        cls.launcher = cls.root / "AEGIS Verify Demo.exe"
        compile_launcher(cls.launcher)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()


@unittest.skipUnless(WINDOWS and CSC.is_file(), "Windows .NET Framework compiler required")
class LauncherTests(LauncherBuild, unittest.TestCase):
    def test_missing_neighbor_executable_has_readable_persistent_error(self):
        with tempfile.TemporaryDirectory(prefix="missing executable ") as folder:
            case = Path(folder)
            launcher = case / self.launcher.name
            shutil.copyfile(self.launcher, launcher)
            data_parent = case / "existing data"
            data_parent.mkdir()
            sentinel = data_parent / "keep.txt"
            sentinel.write_text("keep this existing data", encoding="utf-8")
            result = case / "status.json"
            completed = subprocess.run([str(launcher), "--self-test", str(result), str(case / "stop"),
                                        "--data-parent", str(data_parent)], timeout=20)
            self.assertEqual(completed.returncode, 1)
            status = json.loads(result.read_text(encoding="utf-8-sig"))
            self.assertEqual(status["phase"], "error")
            self.assertIn("aegis.exe", status["error"])
            self.assertTrue(Path(status["log"]).is_file())
            self.assertIn("aegis.exe", Path(status["log"]).read_text(encoding="utf-8-sig"))
            self.assertFalse(status["browser_opened"])
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep this existing data")

    def test_nonzero_demo_exit_stops_its_spawned_child_and_keeps_diagnostics(self):
        # Catch failing startup without closing the job that owns a lingering descendant.
        case = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="failed demo thử ")))
        launcher = case / self.launcher.name
        shutil.copyfile(self.launcher, launcher)
        stub = case / "FailingEngine.cs"
        stub.write_text(r'''
using System;
using System.Diagnostics;
using System.Threading;
class FailingEngine {
    public static int Main(string[] args) {
        if (args.Length == 1 && args[0] == "--linger") { Thread.Sleep(120000); return 0; }
        Process child = Process.Start(new ProcessStartInfo(typeof(FailingEngine).Assembly.Location, "--linger") {
            UseShellExecute = false, CreateNoWindow = true });
        Console.WriteLine("Owned failing demo child: " + child.Id);
        Console.WriteLine("Deliberate demo preparation failure");
        Thread.Sleep(200);
        return 17;
    }
}
''', encoding="utf-8")
        compile_result = subprocess.run([str(CSC), "/nologo", "/target:exe", "/out:" + str(case / "aegis.exe"),
                                         str(stub)], capture_output=True, text=True, timeout=30)
        self.assertEqual(compile_result.returncode, 0, compile_result.stdout + compile_result.stderr)
        data_parent = case / "existing data"
        data_parent.mkdir()
        result = case / "status.json"
        process = subprocess.Popen([str(launcher), "--self-test", str(result), str(case / "stop"),
                                    "--data-parent", str(data_parent)])
        self.addCleanup(stop_process, process)
        self.assertEqual(process.wait(timeout=20), 1)
        status = json.loads(result.read_text(encoding="utf-8-sig"))
        self.assertEqual(status["phase"], "error")
        self.assertIn("exit 17", status["error"])
        log = Path(status["log"]).read_text(encoding="utf-8-sig")
        self.assertIn("Deliberate demo preparation failure", log)
        pids = status["child_pids"]
        pids += [int(line.rsplit(" ", 1)[1]) for line in log.splitlines()
                 if line.startswith("Owned failing demo child: ")]
        self.assertGreaterEqual(len(set(pids)), 2)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and any(process_alive(pid) for pid in pids):
            time.sleep(0.1)
        self.assertFalse(any(process_alive(pid) for pid in pids), "Failure left an owned process running")
        self.assertTrue(Path(status["session"]).is_dir())

    def test_url_and_readiness_contracts_reject_wrong_servers_and_partial_data(self):
        # Catch accepting an arbitrary log URL or opening before the actual data is ready.
        harness = self.root / "Contracts.cs"
        harness.write_text(r'''
using System;
using AegisDemo;
class LauncherContracts {
    static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    public static int Main() {
        Uri uri;
        string host = System.Net.IPAddress.Loopback.ToString();
        string actual = "dashboard: http://" + host + ":49153/ (reports: 12, scenarios: yes, static: yes); Ctrl+C to stop";
        Check(LauncherSession.TryDashboardUrl(actual, out uri) && uri.Port == 49153, "actual announcement");
        string[] invalid = { "http://example.com/", "https://localhost/", "http://localhost:1/extra",
            "http://user@localhost:1/", "http://localhost:1/?query", "http://localhost:1/#fragment" };
        foreach (string candidate in invalid)
            Check(!LauncherSession.TryDashboardUrl("dashboard: " + candidate + " (reports: 12)", out uri), "unsafe URL accepted");
        Check(!LauncherSession.TryDashboardUrl("error: " + actual, out uri), "wrong announcement prefix");
        string reports = "{\"kind\":\"report_index\",\"reports\":[";
        for (int n = 0; n < 12; n++) reports += (n == 0 ? "" : ",") + "{\"name\":\"r" + n + ".json\",\"error\":null,\"kind\":\"evaluation\"}";
        reports += "]}";
        string scenarios = "{\"kind\":\"scenario_index\",\"registry\":{\"configured\":true,\"manifest_count\":6,\"errors\":[],\"error\":null},\"scenarios\":[{},{},{},{},{},{}]}";
        Check(LauncherSession.ReadyIndexes(reports, scenarios), "valid indexes");
        Check(!LauncherSession.ReadyIndexes(reports.Replace("report_index", "wrong"), scenarios), "wrong report kind");
        Check(!LauncherSession.ReadyIndexes(reports.Replace("\"error\":null", "\"error\":{}"), scenarios), "unreadable reports");
        Check(!LauncherSession.ReadyIndexes(reports, scenarios.Replace("true", "false")), "unconfigured registry");
        Check(!LauncherSession.ReadyIndexes(reports, scenarios.Replace("6,", "5,")), "partial registry");
        Check(!LauncherSession.ReadyIndexes("not json", scenarios), "malformed index");
        return 0;
    }
}
''', encoding="utf-8")
        contracts = self.root / "Contracts.exe"
        compile_launcher(contracts, harness)
        completed = subprocess.run([str(contracts)], capture_output=True, timeout=20)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))


@unittest.skipUnless(WINDOWS and CSC.is_file() and REAL_EXE, "Set AEGIS_DEMO_TEST_EXE to opt in to real 0.4.0 integration")
class RealDemoTests(LauncherBuild, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.engine = Path(REAL_EXE).resolve(strict=True)
        cls.engine_hash = hashlib.sha256(cls.engine.read_bytes()).hexdigest()
        shutil.copyfile(cls.engine, cls.root / "aegis.exe")

    @classmethod
    def tearDownClass(cls):
        try:
            if hashlib.sha256(cls.engine.read_bytes()).hexdigest() != cls.engine_hash:
                raise AssertionError("Release executable changed")
        finally:
            super().tearDownClass()

    def start_demo(self, case):
        data_parent = case / "existing dữ liệu"
        data_parent.mkdir(exist_ok=True)
        sentinel = data_parent / "keep.txt"
        sentinel.write_text("existing reports are preserved", encoding="utf-8")
        result, stop = case / "status.json", case / "stop"
        result.unlink(missing_ok=True)
        stop.unlink(missing_ok=True)
        process = subprocess.Popen([str(self.launcher), "--self-test", str(result), str(stop),
                                    "--data-parent", str(data_parent)])
        self.addCleanup(stop_process, process)
        status = wait_status(result, "ready", process)
        return process, status, result, stop, sentinel

    def assert_real_ready(self, status):
        uri = urlsplit(status["url"])
        self.assertEqual(uri.scheme, "http")
        self.assertTrue(ipaddress.ip_address(uri.hostname).is_loopback)
        self.assertEqual(status["report_count"], 12)
        self.assertEqual(status["scenario_count"], 6)
        self.assertFalse(status["browser_opened"])
        reports = json.load(HTTP.open(status["url"] + "api/reports", timeout=5))
        scenarios = json.load(HTTP.open(status["url"] + "api/scenarios", timeout=5))
        self.assertEqual(len(reports["reports"]), 12)
        self.assertTrue(all(report["error"] is None and report["kind"] in {"evaluation", "comparison"}
                            for report in reports["reports"]))
        self.assertEqual(len(scenarios["scenarios"]), 6)
        self.assertEqual(scenarios["registry"]["manifest_count"], 6)
        self.assertIn("AEGIS", HTTP.open(status["url"], timeout=5).read().decode("utf-8"))
        self.assertTrue(Path(status["data"]).is_dir())
        self.assertTrue(Path(status["log"]).is_file())
        self.assertGreater(len(status["child_pids"]), 0)

    def test_real_demo_uses_free_port_and_stop_preserves_existing_data(self):
        case = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="real demo dữ liệu ")))
        # Occupy the engine's default port; port 0 must avoid this conflict.
        occupied = socket.socket()
        self.addCleanup(occupied.close)
        try:
            occupied.bind(("localhost", 8765))
            occupied.listen()
        except OSError:
            occupied.close()  # An existing listener already provides the conflict.
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        self.addCleanup(stop_process, unrelated)
        process, status, result, stop, sentinel = self.start_demo(case)
        self.assert_real_ready(status)
        self.assertNotEqual(urlsplit(status["url"]).port, 8765)
        stop.touch()
        self.assertEqual(process.wait(timeout=20), 0)
        stopped = json.loads(result.read_text(encoding="utf-8-sig"))
        self.assertEqual(stopped["phase"], "stopped")
        eventually_stopped(self, status["url"], status["child_pids"])
        self.assertIsNone(unrelated.poll(), "Unrelated process was stopped")
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing reports are preserved")
        self.assertTrue((Path(status["data"]) / "demo-summary.json").is_file())

    def test_forced_launcher_exit_cleans_descendants_and_next_run_uses_fresh_directory(self):
        case = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="forced exit thử ")))
        process, first, _, _, sentinel = self.start_demo(case)
        self.assert_real_ready(first)
        process.kill()
        process.wait(timeout=10)
        eventually_stopped(self, first["url"], first["child_pids"])
        process, second, _, stop, _ = self.start_demo(case)
        self.assert_real_ready(second)
        self.assertNotEqual(first["session"], second["session"])
        self.assertNotEqual(first["data"], second["data"])
        stop.touch()
        self.assertEqual(process.wait(timeout=20), 0)
        self.assertTrue(Path(first["data"]).is_dir())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing reports are preserved")
        eventually_stopped(self, second["url"], second["child_pids"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
