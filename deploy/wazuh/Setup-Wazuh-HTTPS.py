#!/usr/bin/python3
"""Operator-only entrypoint; never import this helper from the AEGIS server."""
import os
import sys
from pathlib import Path

# Read-only check must not emit Python bytecode files. Installed modules are
# copied from a closed manifest; no environment-controlled package search path.
sys.dont_write_bytecode = True
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
sys.path.insert(0, str(Path(__file__).resolve().parent))

from https_setup.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
