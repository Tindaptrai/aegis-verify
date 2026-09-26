# Synthetic Wazuh alert raised from a Suricata alert

`wazuh-suricata-alert.synthetic.json` is an invented test fixture, not a
captured lab record or proof that any scenario passed. Its envelope (one manager
alert object with top-level `rule`, `agent`, `manager`, `decoder`, `location`
and a Suricata EVE alert under `data`, no `_source`) is informed by private
source inspection on 2026-09-21; identifiers, times, addresses (RFC 5737) and
the flow are invented. No private bytes, hostnames, topology or hashes are
included.

The Wazuh receipt `timestamp` and the Suricata `data.timestamp` differ on
purpose: the parser must use the Suricata time and keep the receipt time only
as provenance.

This fixture does not attest to collection completeness, SIEM correlation
across sources, blocked-flow visibility or clock alignment.
