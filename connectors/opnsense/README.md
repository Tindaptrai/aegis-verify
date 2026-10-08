# OPNsense connector

Offline parser `opnsense-filterlog-bsd-v1` for `filterlog` lines that OPNsense sends
over BSD syslog, saved byte-for-byte by the collector (`%rawmsg%`). It does not
accept RFC 5424 syslog and opens no network connection.

Kept separate from the pfSense connector: column 4 is a rule label (UUID for user
rules, MD5 digest for automatic rules) rather than a numeric tracker, and ICMP and
ICMPv6 records end in a single `datalength=N` cell. Year and UTC offset are caller
context, as for pfSense. See `docs/OPNSENSE_FILTERLOG_PARSER.md`.
