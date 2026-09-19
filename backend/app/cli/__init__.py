"""Safe command dispatcher for offline evidence validation."""

import argparse
import os
import sys

from ..intake import IntakeError
from .reporting import render_error, render_report
from .service import evaluate_bundle
from ..compare import compare_runs
from ..dashboard import DEFAULT_HOST, DEFAULT_PORT, serve


class _ArgumentError(Exception):
    pass


class _HelpExit(Exception):
    pass


class _OutputError(Exception):
    pass


class _NullStream:
    def write(self, text):
        return len(text)

    def flush(self):
        return None


def _neutralize_failed_stream(name: str, stream) -> None:
    """Prevent CPython from retrying a known-failed buffered stream at shutdown."""
    try:
        descriptor = stream.fileno()
        if type(descriptor) is not int or descriptor < 0:
            raise ValueError
        null_descriptor = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null_descriptor, descriptor)
        finally:
            if null_descriptor != descriptor:
                os.close(null_descriptor)
        try:
            stream.flush()
        except (OSError, UnicodeError, ValueError):
            pass
        return
    except (OSError, TypeError, AttributeError, ValueError):
        pass

    try:
        stream.close()
    except (OSError, TypeError, AttributeError, ValueError):
        pass
    try:
        replacement = open(os.devnull, "w", encoding="utf-8")
    except (OSError, TypeError, ValueError):
        replacement = _NullStream()
    if getattr(sys, name, None) is stream:
        setattr(sys, name, replacement)


def _write_stream(name: str, text: str) -> bool:
    stream = getattr(sys, name)
    try:
        written = stream.write(text)
        if written != len(text):
            raise OSError
        stream.flush()
        return True
    except (OSError, UnicodeError, TypeError, AttributeError, ValueError):
        _neutralize_failed_stream(name, stream)
        return False


def _emit_error(error: IntakeError, output_format: str) -> bool:
    return _write_stream("stderr", render_error(error, output_format))


class _SafeParser(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        if not message:
            return
        stream = sys.stdout if file is None else file
        if stream is sys.stdout:
            if not _write_stream("stdout", message):
                raise _OutputError
            return
        if stream is sys.stderr:
            if not _write_stream("stderr", message):
                raise _OutputError
            return
        try:
            stream.write(message)
            stream.flush()
        except (OSError, UnicodeError, TypeError, AttributeError, ValueError):
            raise _OutputError from None

    def error(self, _message):
        raise _ArgumentError

    def exit(self, status=0, message=None):
        if message:
            self._print_message(message, sys.stderr)
        if status == 0:
            raise _HelpExit
        raise _ArgumentError


def _parser() -> argparse.ArgumentParser:
    parser = _SafeParser(prog="aegis", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", allow_abbrev=False)
    validate.add_argument("--scenario", required=True)
    validate.add_argument("--fixture", required=True)
    validate.add_argument("--profile")
    validate.add_argument("--context")
    validate.add_argument("--format", choices=("text", "json"), default="text")

    compare = commands.add_parser("compare", allow_abbrev=False)
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--format", choices=("text", "json"), default="text")

    dashboard = commands.add_parser("dashboard", allow_abbrev=False)
    dashboard.add_argument("--reports", required=True)
    dashboard.add_argument("--host", default=DEFAULT_HOST)
    dashboard.add_argument("--port", type=int, default=DEFAULT_PORT)
    dashboard.add_argument("--static")
    dashboard.add_argument("--operations-config")
    return parser


def _selected_error_format(arguments: list[str]) -> str:
    selections = []
    for index, argument in enumerate(arguments):
        if argument == "--format":
            selections.append(arguments[index + 1] if index + 1 < len(arguments) else None)
        elif argument.startswith("--format="):
            selections.append(argument.partition("=")[2])
    return "json" if selections == ["json"] else "text"


def _duplicates(arguments: list[str]) -> bool:
    for option in (
        "--scenario",
        "--fixture",
        "--profile",
        "--context",
        "--before",
        "--after",
        "--format",
        "--reports",
        "--host",
        "--port",
        "--static",
        "--operations-config",
    ):
        if sum(item == option or item.startswith(option + "=") for item in arguments) > 1:
            return True
    return False


def main(argv=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    error_format = _selected_error_format(arguments)
    try:
        if _duplicates(arguments):
            raise _ArgumentError
        options = _parser().parse_args(arguments)
    except _HelpExit:
        return 0
    except _OutputError:
        _emit_error(IntakeError("output_error", stage="output"), error_format)
        return 4
    except _ArgumentError:
        error = IntakeError("invalid_arguments")
        return 2 if _emit_error(error, error_format) else 4

    if options.command == "dashboard":
        if not 0 <= options.port <= 65535:
            error = IntakeError("invalid_arguments")
            return 2 if _emit_error(error, "text") else 4
        try:
            return serve(options.reports, host=options.host, port=options.port,
                         static_dir=options.static, operations_config=options.operations_config,
                         announce=lambda text: _write_stream("stdout", text + "\n"))
        except IntakeError as error:
            return 2 if _emit_error(error, "text") else 4
        except OSError:
            _emit_error(IntakeError("output_error", stage="output"), "text")
            return 4
        except Exception:
            _emit_error(IntakeError("internal_error"), "text")
            return 4

    try:
        if options.command == "validate":
            report = evaluate_bundle(
                options.scenario,
                options.fixture,
                profile=options.profile,
                context=options.context,
            )
        else:
            report = compare_runs(before=options.before, after=options.after)
        rendered = render_report(report, options.format)
    except IntakeError as error:
        return 2 if _emit_error(error, options.format) else 4
    except Exception:
        error = IntakeError("internal_error")
        _emit_error(error, options.format)
        return 4

    if not _write_stream("stdout", rendered):
        error = IntakeError("output_error", stage="output")
        _emit_error(error, options.format)
        return 4
    if options.command != "compare":
        return {
            "Detected": 0,
            "Prevented": 0,
            "Missing telemetry": 1,
            "False negative": 1,
            "Inconclusive": 3,
        }[report["evaluation"]["final_status"]]
    return 0


__all__ = ["main"]
