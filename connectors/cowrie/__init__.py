"""Offline Cowrie connector contracts for Wazuh-exported evidence."""

from .errors import CowrieDiagnostic, CowrieParseError
from .models import CowrieParseResult, CowrieProvenance
from .native import iter_cowrie_file, parse_cowrie_jsonl
from .native_models import CowrieNativeProvenance, CowrieNativeRecord
from .parser import load_cowrie_wazuh_document, parse_cowrie_wazuh_document

__all__ = [
    "CowrieDiagnostic",
    "CowrieNativeProvenance",
    "CowrieNativeRecord",
    "CowrieParseError",
    "CowrieParseResult",
    "CowrieProvenance",
    "load_cowrie_wazuh_document",
    "iter_cowrie_file",
    "parse_cowrie_jsonl",
    "parse_cowrie_wazuh_document",
]
