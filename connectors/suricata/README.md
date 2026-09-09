# Suricata connector

Direction A implements one sanitized Wazuh search-hit with `data.event_type=alert`
and exact `suricata` rule group. Public APIs return CanonicalEventV2 plus frozen
provenance: `parse_suricata_wazuh_document` and `load_suricata_wazuh_document`.

See [Vietnamese walkthrough and B preparation](../../docs/SURICATA_WAZUH_ALERT.md).
`parser.py` owns Wazuh selection/context/evidence and reuses the bounded Wazuh JSON
decoder; `_mapping.py` maps source alert fields without reading Wazuh metadata.
Absent optionals stay null. Flow identity stays exact text in provenance.

Direction B implements direct EVE JSONL alert/flow through
`parse_suricata_eve_jsonl` (atomic bytes) and `iter_suricata_eve_file` (lazy file).
Every physical line yields parsed/skipped provenance unless parsing fails. Explicit
sensor context scopes identity; no global flow-ID assumptions or cross-export dedup.
See [B guide, real-file counts and flow lab gate](../../docs/SURICATA_EVE_JSONL.md).

The B branch is based on reviewed A. Real sanitized fixtures cover ICMP/TCP/UDP
alerts and a DNS skip; standalone flow tests are artificial because user exports
contain zero flow records. Live collection, schema changes and security verdicts
remain outside this milestone. Issue #4 completion still needs human/lab review.
