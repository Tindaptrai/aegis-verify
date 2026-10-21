"""Read-only assets shipped in wheels and frozen Windows distributions."""

from pathlib import Path

from ..intake import IntakeError


def resource_root() -> Path:
    """Resolve relative to the installed package, never CWD or a checkout."""
    root = Path(__file__).resolve().parent / "data"
    if not (root / "bundle.json").is_file():
        raise IntakeError("invalid_input", stage="inputs")
    return root
