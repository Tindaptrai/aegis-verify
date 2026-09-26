# Synthetic Sysmon 3 manager archive

`sysmon3-archive.synthetic.json` is an invented test fixture, not a captured lab
event or proof that a detection/prevention scenario passed. Its envelope and
field representations are informed by private source inspection; identifiers,
times, identities, process paths and documentation-range addresses are invented.
No private archive bytes, credentials, topology or source hash are included.

The input is one manager archive object, not an Indexer search hit. Its distinct
source utcTime, Windows systemTime and manager timestamp exercise the rule that
the parser uses source utcTime, without falling back to another clock.

Raw private evidence and its integrity/acquisition notes remain outside Git.
This synthetic fixture does not attest to collection completeness, blocked-flow
visibility, source clock alignment, NAT mapping or SIEM correlation.
