# Fixture policy

Only sanitized evidence may be committed here. No synthetic event is being added at
repository bootstrap because the product must not present fabricated logs as real
evidence.

## Expected INC-002 files

```text
tests/fixtures/
├── wazuh/inc002.json
├── suricata/inc002-eve.json
├── pfsense/inc002-filterlog.txt
└── cowrie/inc002-cowrie.json
```

Place original exports in `tests/fixtures/raw/` while sanitizing; Git ignores that
directory. Before committing a fixture:

1. Remove credentials, tokens, webhooks, certificate material, and session secrets.
2. Replace real usernames, hostnames, public IPs, domains, and organization details.
3. Keep substituted values consistent across all four sources.
4. Preserve event ordering, rule IDs, ports, and correlations needed by assertions.
5. Scan the staged diff for secrets and manually review every raw-event field.
6. Record the source incident, sanitization date, and reviewer in the pull request.

Use documentation address ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and
`203.0.113.0/24` when an externally routable address must be replaced.
