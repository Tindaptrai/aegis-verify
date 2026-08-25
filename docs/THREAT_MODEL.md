# Threat Model

## Protected assets

- Credentials, tokens, webhooks, certificates, and connector endpoints
- Raw security telemetry that may contain personal or infrastructure identifiers
- Scenario ground truth and detection rules
- Evidence integrity and the mapping from conclusions to raw events
- The lab environment used for safe scenario execution

## Primary risks and controls

| Risk | Control |
| --- | --- |
| Secret or certificate committed to Git | `.gitignore`, `.env.example`, secret scan before push, human review |
| Sensitive identifiers leaked in fixtures | Raw staging path is ignored; fixtures require sanitization review |
| Evidence is fabricated or silently altered | Stable raw references, evidence IDs, immutable committed fixtures |
| Parser guesses missing data | Missing canonical fields remain `null`; parser tests cover omissions |
| Dangerous scenario execution | Safe test payloads, explicit target allowlist, bounded actions, approval |
| Validation overstates confidence | Separate missing telemetry, false negative, prevention, and inconclusive |
| Ground truth drift hides regressions | Ground truth changes require explicit approval and review history |
| Live connector compromises a source | Read-only least-privilege credentials, TLS verification, no secret logging |

## Trust boundaries

1. Raw lab export → sanitization staging area
2. Sanitized fixture → source parser
3. Source parser → canonical event
4. Canonical events + reviewed ground truth → validation engine
5. Validation result → CLI/API/UI consumer

Each boundary must fail closed: malformed input produces an explicit error or
inconclusive result, never a fabricated passing result.

## Fixture sanitization checklist

- Replace real usernames, hostnames, organization names, domains, public IPs, tokens,
  hashes tied to sensitive files, and credential material.
- Use documentation IP ranges when substitution is needed.
- Preserve timestamps, event ordering, ports, rule IDs, and cross-source correlation
  consistently unless those fields are sensitive.
- Verify the fixture contains no password, API key, webhook, private key, or session
  token before staging it in Git.
- Record the transformation in the pull request without disclosing original values.

## Out of scope for the initial milestone

The fixture-driven CLI does not authenticate users, execute autonomous response, or
write to live security systems. These risks must be reassessed before V1 connectors
or a hosted dashboard are enabled.
