# Wazuh connector

V0 implemented profile: one sanitized Wazuh JSON search-hit document containing
Windows Security-Auditing / Security / 4688. Outputs canonical v2 plus immutable
mapping/collector provenance; preserves exact event time and hashes exact bytes.

Public API: `aegis_verify.connectors.wazuh.parse_wazuh_document` and
`load_wazuh_document`. Source parsing lives here, not in the validation engine.

Read [the Vietnamese guide](../../docs/WAZUH_FIXTURE_PARSER.md) for runnable examples,
mapping, limits, collection topology and human lab comparison. Other profiles,
CSV and generic multi-record exports are not implemented by that parser.

Issue #11 adds a bounded read-only Indexer collector for the reviewed Windows
4688, Sysmon 1 and PowerShell 4104 profiles. It reuses the fixture parsers and
retains original response bytes plus traceable hit derivatives. See
[setup, limits and lab validation](../../docs/WAZUH_LIVE_CONNECTOR.md).
Live lab validation and human review remain pending.
