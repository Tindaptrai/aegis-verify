"""Wazuh fixture adapter."""

from .errors import WazuhDiagnostic, WazuhParseError
from .parser import WazuhParseResult, WazuhProvenance, load_wazuh_document, parse_wazuh_document
from .windows_telemetry import (
    WindowsTelemetryProvenance, WindowsTelemetryResult,
    parse_wazuh_sysmon1_document, parse_wazuh_powershell4104_document,
)

__all__ = ['WazuhDiagnostic', 'WazuhParseError', 'WazuhParseResult', 'WazuhProvenance',
           'load_wazuh_document', 'parse_wazuh_document',
           'WindowsTelemetryProvenance', 'WindowsTelemetryResult',
           'parse_wazuh_sysmon1_document', 'parse_wazuh_powershell4104_document']
