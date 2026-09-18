"""Serve reviewed CLI reports to the dashboard over loopback HTTP, read-only.

The server owns no validation logic. It lists ``*.json`` files in one chosen
directory, decodes each with the intake limits, and returns the decoded report
unchanged. A file that fails to decode is reported as malformed with the intake
error code; nothing is repaired or partially returned. The frontend decides how
to present a report and never receives raw evidence bytes from here.

Only GET is accepted, only on loopback by default, and only for names matching
a strict pattern, so no path outside the chosen directory can be addressed.
"""

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
from pathlib import Path
import re

from ..intake import IntakeError, decode_config, local_path, read_local
from ..intake.io import MAX_CONFIG_BYTES

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
INDEX_KIND = "report_index"
INDEX_VERSION = "0.1.0"
REPORT_KINDS = ("evaluation", "comparison")
MAX_REPORTS = 200
MAX_STATIC_BYTES = 8 * 1024 * 1024
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$")
_STATIC_PATH = re.compile(r"^(?:[A-Za-z0-9._-]{1,128}/){0,8}[A-Za-z0-9._-]{1,128}$")
_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml", ".ico": "image/x-icon", ".png": "image/png", ".map": "application/json",
}


def _safe_name(name: str) -> bool:
    return bool(_NAME.match(name)) and ".." not in name


def _summary(report: dict) -> dict:
    """Copy a few identifying fields for the index; missing ones stay null."""
    kind = report.get("kind")
    scenario = report.get("scenario") if type(report.get("scenario")) is dict else {}
    summary = {
        "kind": kind if kind in REPORT_KINDS else None,
        "scenario_id": scenario.get("id") if type(scenario.get("id")) is str else None,
        "scenario_version": scenario.get("version") if type(scenario.get("version")) is str else None,
        "run_id": None,
        "final_status": None,
        "comparison_status": None,
    }
    evaluation = report.get("evaluation")
    if kind == "evaluation" and type(evaluation) is dict:
        summary["run_id"] = evaluation.get("run_id") if type(evaluation.get("run_id")) is str else None
        status = evaluation.get("final_status")
        summary["final_status"] = status if type(status) is str else None
    comparison = report.get("comparison")
    if kind == "comparison" and type(comparison) is dict:
        status = comparison.get("status")
        summary["comparison_status"] = status if type(status) is str else None
    return summary


class ReportStore:
    """Bounded, name-addressed access to the JSON files of one local directory."""

    def __init__(self, reports_dir):
        self.root = local_path(reports_dir, directory=True, stage="inputs")

    def names(self) -> list[str]:
        names = sorted(p.name for p in self.root.iterdir() if p.is_file() and _safe_name(p.name))
        if len(names) > MAX_REPORTS:
            raise IntakeError("resource_limit", stage="inputs")
        return names

    def load(self, name: str) -> dict:
        """Decode one report with the intake limits; raise IntakeError otherwise."""
        if not _safe_name(name):
            raise IntakeError("invalid_arguments", stage="inputs")
        raw = read_local(self.root / name, limit=MAX_CONFIG_BYTES, stage="inputs")
        report = decode_config(raw, stage="inputs")
        if report.get("kind") not in REPORT_KINDS:
            raise IntakeError("invalid_input", stage="inputs", field="kind")
        return report


def build_index(store: ReportStore) -> dict:
    """List every report with a small summary, or its decode error, never both."""
    entries = []
    for name in store.names():
        try:
            entries.append({"name": name, "error": None, **_summary(store.load(name))})
        except IntakeError as error:
            entries.append({"name": name, "error": {"code": error.code, "stage": error.stage,
                                                    "field": error.field},
                            "kind": None, "scenario_id": None, "scenario_version": None,
                            "run_id": None, "final_status": None, "comparison_status": None})
    return {"kind": INDEX_KIND, "version": INDEX_VERSION, "reports": entries}


def _error_body(error: IntakeError) -> dict:
    return {"kind": "error", "error": {"code": error.code, "stage": error.stage,
                                       "field": error.field, "hint": error.hint}}


def _handler(store: ReportStore, static_dir):
    static_root = None if static_dir is None else local_path(static_dir, directory=True, stage="inputs")

    class Handler(BaseHTTPRequestHandler):
        server_version = "AegisDashboard/0.1.0"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            return None

        def _send(self, status, body: bytes, content_type: str):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, payload):
            body = json.dumps(payload, ensure_ascii=True, sort_keys=True,
                              separators=(",", ":"), allow_nan=False).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def _api(self, path: str):
            if path == "/api/reports":
                try:
                    self._json(HTTPStatus.OK, build_index(store))
                except IntakeError as error:
                    self._json(HTTPStatus.UNPROCESSABLE_ENTITY, _error_body(error))
                return
            if path.startswith("/api/reports/"):
                name = path[len("/api/reports/"):]
                if not _safe_name(name):
                    self._json(HTTPStatus.NOT_FOUND, {"kind": "error", "error": {"code": "not_found"}})
                    return
                if not (store.root / name).is_file():
                    self._json(HTTPStatus.NOT_FOUND, {"kind": "error", "error": {"code": "not_found"}})
                    return
                try:
                    self._json(HTTPStatus.OK, store.load(name))
                except IntakeError as error:
                    self._json(HTTPStatus.UNPROCESSABLE_ENTITY, _error_body(error))
                return
            self._json(HTTPStatus.NOT_FOUND, {"kind": "error", "error": {"code": "not_found"}})

        def _static(self, path: str):
            if static_root is None:
                self._json(HTTPStatus.NOT_FOUND, {"kind": "error", "error": {"code": "not_found"}})
                return
            relative = path.lstrip("/") or "index.html"
            if not _STATIC_PATH.match(relative) or ".." in relative:
                self._json(HTTPStatus.NOT_FOUND, {"kind": "error", "error": {"code": "not_found"}})
                return
            target = static_root / relative
            if not target.is_file():
                # Client-side routes fall back to the app shell; assets never do.
                if "." in Path(relative).name:
                    self._json(HTTPStatus.NOT_FOUND, {"kind": "error", "error": {"code": "not_found"}})
                    return
                target = static_root / "index.html"
                if not target.is_file():
                    self._json(HTTPStatus.NOT_FOUND, {"kind": "error", "error": {"code": "not_found"}})
                    return
            try:
                body = read_local(target, limit=MAX_STATIC_BYTES, stage="inputs")
            except IntakeError as error:
                self._json(HTTPStatus.UNPROCESSABLE_ENTITY, _error_body(error))
                return
            content_type = _STATIC_TYPES.get(target.suffix.lower()) or mimetypes.guess_type(target.name)[0] \
                or "application/octet-stream"
            self._send(HTTPStatus.OK, body, content_type)

        def do_GET(self):
            path = self.path.split("?", 1)[0].split("#", 1)[0]
            try:
                if path == "/api" or path.startswith("/api/"):
                    self._api(path)
                else:
                    self._static(path)
            except (OSError, ValueError):
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR,
                           {"kind": "error", "error": {"code": "internal_error"}})

        def do_HEAD(self):
            self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
            self.send_header("Allow", "GET")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD

    return Handler


def make_server(reports_dir, *, host=DEFAULT_HOST, port=DEFAULT_PORT, static_dir=None):
    """Build the loopback server; ``port=0`` picks a free port (tests)."""
    store = ReportStore(reports_dir)
    server = ThreadingHTTPServer((host, port), _handler(store, static_dir))
    server.daemon_threads = True
    return server


def serve(reports_dir, *, host=DEFAULT_HOST, port=DEFAULT_PORT, static_dir=None, announce=print):
    server = make_server(reports_dir, host=host, port=port, static_dir=static_dir)
    bound_host, bound_port = server.server_address[:2]
    announce(f"dashboard: http://{bound_host}:{bound_port}/ (reports: {len(ReportStore(reports_dir).names())}, "
             f"static: {'yes' if static_dir else 'no'}); Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
