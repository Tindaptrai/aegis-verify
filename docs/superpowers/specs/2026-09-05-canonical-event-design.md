# Canonical Event — Issue #1 design

The user approved implementing the event model, input validation, tests, JSON
serialization, and sanitized-record hashing in the current step-by-step session.
Scope comes from PRD, ARCHITECTURE, and the Issue #1 acceptance criteria previously
retrieved in this conversation. The current GitHub issue was not fetched again;
reconcile any subsequent issue edits during review.

## Contract

Use a Pydantic model exported as `aegis_verify.models.CanonicalEvent`, with
`SourceType` and `EventAction` string enums. The import package maps to backend/app.
Require schema version 1.0 (default), event_id, timestamp, source_type,
environment_id, raw_event_ref, raw_event_hash, and ingested_at. Do not generate
IDs or timestamps implicitly. The collector owns those values.

Include nullable asset, hostname, username, process, network, action, rule,
signature, severity, and technique context from the provided roadmap. Nullable
event_provider distinguishes the connector from the original event provider,
such as Sysmon carried through Wazuh. Unknown provider strings are preserved.
Missing optional values serialize as null. Technique IDs are an optional tuple
of nonblank strings in Python and an array in JSON; no mapping is inferred.

Reject extra fields, empty identifiers, invalid hashes, wrong scalar types,
out-of-range ports, numeric IP values, and naive or ambiguous timestamps.
Accept explicitly offset RFC 3339 timestamps with seconds and up to six fractional
digits, or aware datetime objects; normalize to UTC. Reject -00:00 (unknown offset).
The model is frozen and does not evaluate security meaning or resolve paths.

`event_id` is the ID referenced by future validation result evidence_ids.
The caller scopes it to an environment and raw-record identity and keeps it
stable on replay. Hash is not an event ID: duplicate raw records can share hashes.

`hash_raw_event(raw_record: bytes) -> str` hashes exact sanitized record bytes
using SHA-256, without decoding, stripping whitespace, parsing JSON, or normalizing
newlines. A future parser must retain/hash the same record slice; retained record
terminators participate in the hash. This helper neither reads files nor sanitizes
raw data. Hash validity in the schema only checks syntax, not provenance authenticity.

## Dependencies and alternatives

Pydantic provides validation, JSON round trips and generated JSON Schema for future
API reuse. Dataclasses would need bespoke validators; JSON-Schema-only validation
would not provide the Python domain model. Use Pydantic for this contract.
pytest supplies parametrized boundary tests. SHA-256 uses standard-library hashlib.
setuptools enables a normal editable/installable package without PYTHONPATH hacks.
Pin runtime/test dependencies to the versions actually installed in the session.

## Acceptance and safety

Tests cover minimal and full events, optional nulls, required values, bad types,
timezone normalization, stable serialization, version/source/action validation,
IP/port boundaries, unknown fields, frozen data, and known SHA-256 vectors.
All examples are artificial schema test data, not source-tool logs or incident evidence.
No parser, scenario, detection rule, fixture export, engine, or live API changes.
No merge before human review; schema tests do not validate detection correctness.
