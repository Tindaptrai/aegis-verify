"""Safe command dispatcher for offline evidence validation."""

import argparse
import sys

from ..intake import IntakeError
from .reporting import render_error, render_report
from .service import evaluate_bundle


class _ArgumentError(Exception):
    pass


class _HelpExit(Exception):
    pass


class _SafeParser(argparse.ArgumentParser):
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
    for option in ("--scenario", "--fixture", "--profile", "--context", "--format"):
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
    except _ArgumentError:
        error = IntakeError("invalid_arguments")
        try:
            sys.stderr.write(render_error(error, error_format))
            sys.stderr.flush()
        except (OSError, UnicodeError):
            pass
        return 2

    try:
        report = evaluate_bundle(
            options.scenario,
            options.fixture,
            profile=options.profile,
            context=options.context,
        )
        rendered = render_report(report, options.format)
    except IntakeError as error:
        try:
            sys.stderr.write(render_error(error, options.format))
            sys.stderr.flush()
        except (OSError, UnicodeError):
            pass
        return 2
    except Exception:
        error = IntakeError("internal_error")
        try:
            sys.stderr.write(render_error(error, options.format))
            sys.stderr.flush()
        except (OSError, UnicodeError):
            pass
        return 4

    try:
        written = sys.stdout.write(rendered)
        if written != len(rendered):
            raise OSError
        sys.stdout.flush()
    except (OSError, UnicodeError):
        error = IntakeError("output_error", stage="output")
        try:
            sys.stderr.write(render_error(error, options.format))
            sys.stderr.flush()
        except (OSError, UnicodeError):
            pass
        return 4
    return {
        "Detected": 0,
        "Prevented": 0,
        "Missing telemetry": 1,
        "False negative": 1,
        "Inconclusive": 3,
    }[report["evaluation"]["final_status"]]


__all__ = ["main"]
