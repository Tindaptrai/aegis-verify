"""Safe, fixture-first intake primitives for the offline CLI."""

from .errors import IntakeError
from .io import bundle_path, decode_config, local_path, read_local

__all__ = ["IntakeError", "bundle_path", "decode_config", "local_path", "read_local"]
