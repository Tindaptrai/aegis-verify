# pfSense connector

V0 input: sanitized `filterlog` fixture. Expected source data includes pass/block,
addresses, ports, protocol, interface, and NAT/firewall context when present. Live
syslog or export access is V1.

## Hostname-less BSD syslog

The offline parser accepts BSD filterlog headers with or without a hostname.
When absent, canonical `hostname` remains `null`; caller-configured `sensor_id`
stays separate in provenance. It must not be copied into source hostname.
Consumers may use a separately configured sensor display label, explicitly
identified as configuration rather than a value observed in the log.

Year and UTC offset remain explicit caller context. Raw-byte hashing and
evidence identity are unchanged; the parser never inserts missing header text.
When extracting `full_log` from a manager archive, its UTF-8 bytes are a
derivative, not an original native file: retain the parent archive/hash and
extraction provenance separately. This parser does not import archive envelopes
or implement a dashboard display-label mapping.
