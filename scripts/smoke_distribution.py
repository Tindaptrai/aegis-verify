"""Exercise an installed wheel or EXE outside source, using only stdlib tooling."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


EXPECTED = {
    "scn002-control": ("002", "scn002-lab-sanitized/control", "Inconclusive", 3),
    "scn002-block": ("002", "scn002-lab-sanitized/block", "Prevented", 0),
    "scn003-detected": ("003", "scn003-lab-sanitized", "Detected", 0),
    "scn004-block-siem": ("004", "scn004-lab-c-sanitized/block-siem", "Prevented", 0),
    "scn004-block": ("004", "scn004-lab-c-sanitized/block", "Inconclusive", 3),
    "scn004-sensor-down": ("004", "scn004-lab-c-sanitized/sensor-down", "Inconclusive", 3),
    "scn005-synthetic": ("005", "scn005-elastic-synthetic", "Detected", 0),
    "scn006-synthetic": ("006", "scn006-elastic-synthetic", "Detected", 0),
}


def digest_tree(root):
    return {p.relative_to(root).as_posix(): sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


def smoke(command, work, environment):
    def run(*arguments, expected=0):
        result = subprocess.run([*command, *map(str, arguments)], cwd=work, env=environment,
                                capture_output=True, encoding="utf-8", timeout=120)
        if result.returncode != expected:
            raise AssertionError({"arguments": list(map(str, arguments)), "exit": result.returncode,
                                  "stdout": result.stdout, "stderr": result.stderr})
        return result.stdout

    version = run("--version").strip()
    run("--help")
    kit = work / "demo đã làm sạch"
    summary = json.loads(run("demo", "--out", kit))
    assert summary["network_access"] is False and summary["scenario_execution"] is False
    notices = (kit / "licenses/frontend.txt").read_text(encoding="utf-8")
    assert all(name in notices for name in ("React", "react-dom", "scheduler", "Permission is hereby granted"))
    assert {e["case"]: e["final_status"] for e in summary["evaluations"]} == {
        name: values[2] for name, values in EXPECTED.items()}
    assert {c["case"]: c["status"] for c in summary["comparisons"]} == {
        "scn002-control-to-block": "Inconclusive", "synthetic-gap-to-fix": "Regression Passed"}
    for name, (number, fixture, expected_status, code) in EXPECTED.items():
        manifest, = (kit / "scenarios").glob("SCN-" + number + "-*.yaml")
        report = json.loads(run("validate", "--scenario", manifest, "--fixture", kit / "fixtures" / fixture,
                               "--profile", kit / "scenarios/profiles" / ("scn-" + number) / "profile.json",
                               "--format", "json", expected=code))
        assert report["evaluation"]["final_status"] == expected_status
        assert report["evaluation"]["evidence_index"], name
    reports = kit / "reports"
    comparison = json.loads(run("compare", "--before", reports / "synthetic-before-false-negative.json",
                                "--after", reports / "synthetic-after-detected.json", "--format", "json"))
    assert comparison["comparison"]["status"] == "Regression Passed"
    before = digest_tree(kit)
    run("demo", "--out", kit, expected=2)
    assert digest_tree(kit) == before, "existing output was modified"
    # Exercise actual hash rejection without altering packaged or original demo bytes.
    evidence = kit / "fixtures/scn005-elastic-synthetic/sysmon1.json"
    original = evidence.read_bytes()
    try:
        evidence.write_bytes(original + b" ")
        manifest, = (kit / "scenarios").glob("SCN-005-*.yaml")
        run("validate", "--scenario", manifest, "--fixture", evidence.parent,
            "--profile", kit / "scenarios/profiles/scn-005/profile.json", "--format", "json", expected=2)
    finally:
        evidence.write_bytes(original)
    (reports / "malformed.json").write_text('{"kind":', encoding="utf-8")
    (reports / "unsupported.json").write_text('{"kind":"unsupported"}', encoding="utf-8")
    before = digest_tree(kit)
    log_path = work / "dashboard.log"
    with log_path.open("w", encoding="utf-8") as log:
        kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {}
        process = subprocess.Popen([*command, "dashboard", "--bundled", "--reports", str(reports),
                                    "--port", "0"], cwd=work, env=environment, stdout=log, stderr=log, **kwargs)
        try:
            url = None
            for _ in range(300):
                if process.poll() is not None:
                    raise AssertionError(log_path.read_text(encoding="utf-8"))
                match = re.search(r"http://127\.0\.0\.1:\d+/", log_path.read_text(encoding="utf-8"))
                if match:
                    url = match.group()
                    break
                time.sleep(.1)
            assert url, "dashboard startup timeout"

            def fetch(path, expected=200):
                try:
                    response = urllib.request.urlopen(url + path.lstrip("/"), timeout=10)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    assert response.code == expected, (path, response.code)
                    return response.read()

            html = fetch("").decode("utf-8")
            assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', html)
            assert assets
            for asset in assets:
                assert fetch(asset)
            index = json.loads(fetch("api/reports"))
            assert len(index["reports"]) == 14
            for row in index["reports"]:
                fetch("api/reports/" + row["name"], 422 if row["error"] else 200)
            catalog = json.loads(fetch("api/scenarios"))
            assert not catalog["registry"]["errors"]
            assert {s["id"] for s in catalog["scenarios"]} == {f"SCN-{n:03}" for n in range(1, 7)}
            for row in catalog["scenarios"]:
                fetch("api/scenarios/" + row["id"])
            fetch("api/system/status")
            fetch("api/operations/bootstrap", 404)
        finally:
            if process.poll() is None:
                if os.name == "nt":
                    # A onefile bootloader owns a child process. Kill only this
                    # test's process tree so its server cannot survive the probe.
                    subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/taskkill.exe"),
                                    "/PID", str(process.pid), "/T", "/F"],
                                   capture_output=True, timeout=15, check=True)
                else:
                    process.terminate()
                process.wait(timeout=15)
    assert digest_tree(kit) == before, "read-only dashboard changed its inputs"
    return {"passed": True, "version": version, "validation_cases": 8,
            "scenario_manifests": 6, "comparisons": 2, "demo_reports": 12,
            "malformed_reports_rejected": 2, "static_assets": assets,
            "existing_output_preserved": True, "hash_mismatch_rejected": True,
            "dashboard_read_only": True, "frontend_notices_in_demo": True, "work": str(work)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--python", type=Path)
    target.add_argument("--exe", type=Path)
    parser.add_argument("--result", type=Path)
    options = parser.parse_args()
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME"):
        environment.pop(key, None)
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    command = [str(options.exe.resolve())] if options.exe else [
        str(options.python.resolve()), "-I", "-X", "utf8", "-m", "aegis_verify"]
    if options.exe and os.name == "nt":
        environment["PATH"] = os.pathsep.join([str(Path(os.environ["SystemRoot"]) / "System32"),
                                                os.environ["SystemRoot"]])
    with tempfile.TemporaryDirectory(prefix="aegis ngoài source ") as temporary:
        work = Path(temporary).resolve()
        checkout = Path(__file__).resolve().parents[1]
        assert not work.is_relative_to(checkout)
        if options.python:
            info = subprocess.run([str(options.python.resolve()), "-I", "-c",
                "import aegis_verify,json,sys; print(json.dumps({'module':aegis_verify.__file__,'prefix':sys.prefix}))"],
                cwd=work, env=environment, capture_output=True, text=True, check=True)
            origin = json.loads(info.stdout)
            assert Path(origin["module"]).resolve().is_relative_to(Path(origin["prefix"]).resolve()), origin
        result = smoke(command, work, environment)
        result["artifact"] = str((options.exe or options.python).resolve())
        result["os"] = os.name
        result["python_and_node_removed_from_runtime_path"] = bool(options.exe and os.name == "nt")
        result["clean_windows_vm_tested"] = False
        if options.result:
            options.result.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    main()
