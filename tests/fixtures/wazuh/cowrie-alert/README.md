# Synthetic Wazuh alert raised from a Cowrie login failure

`wazuh-cowrie-alert.synthetic.json` is an invented test fixture, not a
captured lab record or proof that any scenario passed. Its envelope is one
manager alert object (top-level `rule`, `agent`, `manager`, `decoder`,
`location`, the Cowrie event under `data`, no `_source`), shaped after the
manager alerts seen for Suricata in SCN-002 and the Cowrie JSON log format:
numeric Cowrie fields arrive as strings because the Wazuh JSON decoder
stringifies them. Identifiers, times, addresses (RFC 5737), the session and the
username marker are invented.

**No password is present.** A real Cowrie login event carries the typed one
and Wazuh keeps it in `data`; the parser never reads that member, and a
committed fixture must not contain one.

**No ports and no destination address either**, on purpose: a real
`cowrie.login.failed` record carries only `src_ip`, `session`, `protocol`,
`username` and `timestamp` (see the sanitized samples under
`tests/fixtures/cowrie/`). Only `cowrie.session.connect` has the full tuple.
The session key is therefore what ties a login failure to its connection.

The Wazuh receipt `timestamp` and the Cowrie `data.timestamp` differ on
purpose: the parser must use the Cowrie time and keep the receipt time only as
provenance.

A real, sanitized manager-alert sample for rule `100300` or the SCN-003 rule
must be reviewed before live acceptance; until then this fixture only shows
the software path. It does not attest to collection completeness, decoy
routing, NAT behaviour or clock alignment.
