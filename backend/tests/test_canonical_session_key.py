"""`session_key` is an optional, opaque canonical correlation field (#76).

Connectors derive it from their own session namespace; the engine can filter
and join on it, but it is never a target binding and never replaces evidence
identity. Both Cowrie parsers expose it on the canonical event.
"""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis_verify.connectors import cowrie
from aegis_verify.models import CanonicalEvent, CanonicalEventV2
from aegis_verify.validation import contracts as c

ROOT = Path(__file__).resolve().parents[2]
VALID = "cowrie:session-v1:" + "a" * 64
BASE_V2 = {"event_id": "unit-event", "timestamp": "2026-01-01T00:00:00Z", "ingested_at": "2026-01-01T00:00:01Z",
           "source_type": "cowrie", "environment_id": "unit-lab", "raw_event_ref": "unit-only/record:1",
           "raw_event_hash": "a" * 64}


def test_v2_accepts_the_opaque_key_and_defaults_to_null():
    assert CanonicalEventV2.model_validate(BASE_V2).session_key is None
    event = CanonicalEventV2.model_validate(BASE_V2 | {"session_key": VALID})
    assert event.session_key == VALID
    assert json.loads(event.model_dump_json())["session_key"] == VALID
    assert CanonicalEvent.model_validate({**BASE_V2, "session_key": VALID}).session_key == VALID


@pytest.mark.parametrize("value", [
    "test-session", "", " ", "cowrie:session-v1:" + "A" * 64, "wazuh:session-v1:" + "a" * 64,
    "cowrie:session-v1:" + "a" * 63, "cowrie:session-v2:" + "a" * 64, 12345,
], ids=["raw-session", "empty", "blank", "uppercase-hex", "other-namespace", "short-digest", "other-version", "int"])
def test_v2_rejects_anything_but_the_namespace_and_digest_shape_without_echoing_it(value):
    with pytest.raises(ValidationError) as raised:
        CanonicalEventV2.model_validate(BASE_V2 | {"session_key": value})
    if str(value).strip():
        assert str(value) not in str(raised.value)


def test_engine_can_filter_and_join_on_it_but_never_bind_a_target_to_it():
    assert "session_key" in c.FILTER_FIELDS and "session_key" in c.JOIN_FIELDS
    assert "session_key" not in c.TARGET_FIELDS
    c.Predicate(field="session_key", op="exists")
    c.Predicate(field="session_key", op="eq", value=VALID)
    c.JoinPair(target_field="session_key", anchor_field="session_key")
    with pytest.raises(ValidationError):
        c.JoinPair(target_field="session_key", anchor_field="src_port")
    with pytest.raises(ValidationError):
        # A scope with only a session_key binding has no explicit target binding.
        c.AssertionRule(assertion_id="A", role="telemetry", capability="supported", source_type="cowrie",
                        scope=[{"field": "session_key", "op": "eq", "binding": "k"}])


def test_the_wazuh_wrapped_cowrie_parser_exposes_the_same_key_as_its_provenance():
    raw = (ROOT / "tests" / "fixtures" / "cowrie" / "login-failed.sanitized.json").read_bytes()
    result = cowrie.parse_cowrie_wazuh_document(raw, source_ref="fixture-a", environment_id="fixture-lab",
                                                sensor_id="fixture-host-01", ingested_at="2026-05-06T09:00:00Z")
    assert result.event.session_key == result.provenance.session_key
    assert result.event.session_key.startswith("cowrie:session-v1:")
    assert "fixture-session-03" not in result.event.model_dump_json()


def test_the_native_cowrie_parser_exposes_one_key_for_every_record_of_a_session():
    raw = (ROOT / "tests" / "fixtures" / "cowrie" / "native" / "session-sequence.sanitized.jsonl").read_bytes()
    records = cowrie.parse_cowrie_jsonl(raw, source_ref="fixture-b", environment_id="fixture-lab",
                                        sensor_id="fixture-host-01", ingested_at="2026-05-06T09:00:00Z")
    parsed = [record for record in records if record.status == "parsed"]
    keys = {record.event.session_key for record in parsed}
    assert len(parsed) == 7 and len(keys) == 1 and next(iter(keys)).startswith("cowrie:session-v1:")
    assert all(record.event.session_key == record.provenance.session_key for record in parsed)
    assert all(record.provenance.session_key is None for record in records if record.status == "skipped")
