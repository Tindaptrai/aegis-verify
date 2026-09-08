"""Wazuh fixture adapter."""

from .errors import WazuhDiagnostic, WazuhParseError
from .parser import WazuhParseResult, WazuhProvenance, load_wazuh_document, parse_wazuh_document

__all__ = ['WazuhDiagnostic', 'WazuhParseError', 'WazuhParseResult', 'WazuhProvenance',
           'load_wazuh_document', 'parse_wazuh_document']
