"""Offline Suricata connectors: Wazuh alert wrapper (A) and direct EVE JSONL (B)."""
from .errors import SuricataDiagnostic, SuricataParseError
from .models import SuricataParseResult, SuricataProvenance
from .parser import load_suricata_wazuh_document, parse_suricata_wazuh_document
from .eve import iter_suricata_eve_file, parse_suricata_eve_jsonl
from .eve_models import SuricataEveProvenance, SuricataEveRecord

__all__ = ['SuricataDiagnostic', 'SuricataParseError', 'SuricataParseResult',
           'SuricataProvenance', 'load_suricata_wazuh_document', 'parse_suricata_wazuh_document',
           'iter_suricata_eve_file', 'parse_suricata_eve_jsonl', 'SuricataEveProvenance', 'SuricataEveRecord']
