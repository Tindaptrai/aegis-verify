# Wazuh fixture — Windows Security 4688

Source: one Wazuh Dashboard Document Details JSON supplied by the repository owner.
Sanitized on 2026-09-08; full sanitized payload reviewed by the implementing agent
before adding. Human mapping review remains pending; this is not assigned INC-002
or claimed to be evidence of an attack or a detection/prevention result.

Replacements: agent IP -> documentation range, machine/collector names and agent
ID -> lab pseudonyms; usernames and names in message substituted consistently.
Windows well-known SIDs/provider GUID, rule/event/record IDs, timestamps, process
paths/command line and event structure retained. No credentials were identified.
Raw original remains outside the repository. Parser is NOT a sanitizer.

`win4688.sanitized.json` is byte-for-byte copied from the reviewed sanitized file.
SHA-256: `27813eae73a3276ab9bc61aeccf8572d0ba5309692ae4a888f7b8f7e55527571`.
Preserve its bytes, line endings and existing escaping; do not normalize slashes.
The owner confirmed direct agent collection on the originating Windows machine.
This declaration only applies to this sample, not all Wazuh records.

Tests that mutate the decoded sample create artificial variants in memory and do
not rewrite this fixture or assert those variants occurred in the lab.

Future INC-002 export remains a separate reviewed `inc002.json`; follow the parent
fixture policy and preserve safe correlation fields. This sample does not replace it.
