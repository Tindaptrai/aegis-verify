# Suricata connector

Direction A implements one sanitized Wazuh search-hit with `data.event_type=alert`
and exact `suricata` rule group. Public APIs return CanonicalEventV2 plus frozen
provenance: `parse_suricata_wazuh_document` and `load_suricata_wazuh_document`.

See [Vietnamese walkthrough and B preparation](../../docs/SURICATA_WAZUH_ALERT.md).
`parser.py` owns Wazuh selection/context/evidence and reuses the bounded Wazuh JSON
decoder; `_mapping.py` maps source alert fields without reading Wazuh metadata.
Absent optionals stay null. Flow identity stays exact text in provenance.

Direct EVE JSONL and standalone flow fixtures are planned direction B (still V0
offline), not implemented here. Live collection remains deferred. This milestone
does not complete Issue #4, alter the canonical schema, or issue security verdicts.
