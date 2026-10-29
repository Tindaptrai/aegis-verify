"""Fixed-vocabulary root CLI; stdout is machine-readable, never exception text."""
import argparse
import json
import re

from .contracts import SetupError
from .host import LinuxHost
from .transaction import Coordinator


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SetupError("profile_invalid")


def main(argv=None, *, coordinator=None):
    try:
        parser = Parser(description="Optional Wazuh HTTPS operator kit; local success requires external validation.")
        commands = parser.add_subparsers(dest="command", required=True)
        for name in ("check", "apply", "guard-ensure", "guard-verify"):
            command = commands.add_parser(name)
            command.add_argument("--profile", required=True)
            if name == "apply":
                command.add_argument("--profile-sha256", required=True)
                command.add_argument("--check-sha256", required=True)
        commands.add_parser("status")
        commands.add_parser("rollback")
        args = parser.parse_args(argv)
        c = coordinator if coordinator is not None else Coordinator(LinuxHost())
        if coordinator is None:
            c.host.require_root()
        if args.command == "check":
            result = c.check(args.profile)
        elif args.command == "apply":
            if any(not re.fullmatch("[0-9a-f]{64}", value) for value in (args.profile_sha256, args.check_sha256)):
                raise SetupError("profile_invalid")
            result = c.apply(args.profile, args.profile_sha256, args.check_sha256)
        elif args.command == "status":
            if coordinator is None:
                c.host.prepare_state()
            result = c.status()
        elif args.command == "rollback":
            result = c.rollback()
        else:
            result = c.host.guard(args.profile, ensure=args.command == "guard-ensure")
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        code = exc.code if isinstance(exc, SetupError) else "setup_failed"
        print(json.dumps({"status": "error", "error": code}, separators=(",", ":")))
        return 1
