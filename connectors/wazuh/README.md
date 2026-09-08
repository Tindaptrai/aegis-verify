# Wazuh connector

V0 implemented profile: one sanitized Wazuh JSON search-hit document containing
Windows Security-Auditing / Security / 4688. Outputs canonical v2 plus immutable
mapping/collector provenance; preserves exact event time and hashes exact bytes.

Public API: `aegis_verify.connectors.wazuh.parse_wazuh_document` and
`load_wazuh_document`. Source parsing lives here, not in the validation engine.

Read [the Vietnamese guide](../../docs/WAZUH_FIXTURE_PARSER.md) for runnable examples,
mapping, limits, collection topology and human lab comparison. Other profiles,
CSV, multi-record exports and live API/Indexer access are not implemented.
