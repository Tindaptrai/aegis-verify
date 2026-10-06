"""Offline OPNsense filterlog connector (BSD syslog as received from the firewall)."""

from ._context import make_context, source_timestamp
from .errors import OpnSenseDiagnostic, OpnSenseParseError
from .models import OpnSenseContext, OpnSenseProvenance, OpnSenseRecord
from .parser import iter_opnsense_filterlog_file, parse_opnsense_filterlog

__all__ = [
    "OpnSenseContext",
    "OpnSenseDiagnostic",
    "OpnSenseParseError",
    "OpnSenseProvenance",
    "OpnSenseRecord",
    "make_context",
    "source_timestamp",
    "iter_opnsense_filterlog_file",
    "parse_opnsense_filterlog",
]
