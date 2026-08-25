# Connectors

V0 connectors parse sanitized fixture files. V1 live connectors are added only after
the canonical model and validation engine work end to end.

Every connector must emit canonical events, preserve a stable `raw_event_ref`, leave
unknown fields as `null`, and avoid logging credentials or raw sensitive content.
