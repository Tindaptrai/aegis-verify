"""Wazuh fixture adapter."""

from .errors import WazuhDiagnostic, WazuhParseError
from .parser import WazuhParseResult, WazuhProvenance, load_wazuh_document, parse_wazuh_document
from .windows_telemetry import (
    WindowsTelemetryProvenance, WindowsTelemetryResult,
    parse_wazuh_sysmon1_document, parse_wazuh_powershell4104_document,
)
from .network_telemetry import (
    NetworkTelemetryProvenance, NetworkTelemetryResult,
    parse_wazuh_sysmon3_archive_record,
)
from .suricata_alert import (
    SuricataAlertProvenance, SuricataAlertResult,
    parse_wazuh_suricata_alert_record,
)
from .snort_alert import (
    SnortAlertProvenance, SnortAlertResult,
    parse_wazuh_snort_alert_record,
)
from .cowrie_alert import (
    CowrieAlertProvenance, CowrieAlertResult,
    parse_wazuh_cowrie_alert_record,
)

__all__ = ['WazuhDiagnostic', 'WazuhParseError', 'WazuhParseResult', 'WazuhProvenance',
           'load_wazuh_document', 'parse_wazuh_document',
           'WindowsTelemetryProvenance', 'WindowsTelemetryResult',
           'parse_wazuh_sysmon1_document', 'parse_wazuh_powershell4104_document',
           'NetworkTelemetryProvenance', 'NetworkTelemetryResult',
           'parse_wazuh_sysmon3_archive_record',
           'SuricataAlertProvenance', 'SuricataAlertResult',
           'parse_wazuh_suricata_alert_record',
           'SnortAlertProvenance', 'SnortAlertResult',
           'parse_wazuh_snort_alert_record',
           'CowrieAlertProvenance', 'CowrieAlertResult',
           'parse_wazuh_cowrie_alert_record']
