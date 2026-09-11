"""Synthetic Cowrie mapping tests; no payload here is lab evidence."""

import importlib
import importlib.util
import json

import pytest


CONTEXT = {
    "source_ref": "unit-cowrie.json",
    "environment_id": "unit-lab",
    "sensor_id": "unit-honeypot",
    "ingested_at": "2026-01-02T03:05:00Z",
}
BASE_DATA = {
    "eventid": "cowrie.login.failed",
    "timestamp": "2026-01-02T03:04:05.123456+0000",
    "src_ip": "192.0.2.20",
    "src_port": "54321",
    "dst_ip": "2001:db8::10",
    "dst_port": 22,
    "protocol": "ssh",
    "session": "test-session",
    "sensor": "source-sensor",
    "uuid": "source-uuid",
    "arch": "amd64",
    "username": "unit-user",
    "password": "synthetic-credential-only",
    "input": "echo synthetic-command",
}
_MISSING = object()


def raw_document(*, eventid="cowrie.login.failed", session="test-session", data=None):
    payload = BASE_DATA | {"eventid": eventid}
    if session is _MISSING:
        payload.pop("session", None)
    else:
        payload["session"] = session
    if data:
        for key, value in data.items():
            if value is _MISSING:
                payload.pop(key, None)
            else:
                payload[key] = value
    document = {
        "_source": {
            "id": "unit-alert-001",
            "timestamp": "2026-01-02T03:04:06.123+0000",
            "rule": {"id": "55001", "level": 3, "groups": ["cowrie", "honeypot"]},
            "agent": {"id": "001", "name": "unit-agent", "ip": "192.0.2.10"},
            "manager": {"name": "unit-manager"},
            "data": payload,
            "full_log": "synthetic duplicate container is intentionally ignored",
        }
    }
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode()


def api():
    return importlib.import_module("aegis_verify.connectors.cowrie")


def parse(raw, **changes):
    parser = getattr(api(), "parse_cowrie_wazuh_document", None)
    assert callable(parser), "Cowrie public parser API is missing"
    return parser(raw, **(CONTEXT | changes))


def test_public_parser_exists():
    assert importlib.util.find_spec("aegis_verify.connectors.cowrie") is not None
    assert callable(getattr(api(), "parse_cowrie_wazuh_document", None))


def test_login_failed_is_a_fact_with_preserved_session():
    result = parse(raw_document(eventid="cowrie.login.failed", session="test-session"))
    assert result.event.source_type == "cowrie"
    assert result.event.event_provider == "cowrie"
    assert result.event.event_action == "login"
    assert result.provenance.authentication_outcome == "failure"
    assert result.provenance.session == "test-session"
    assert result.provenance.session_key.startswith("cowrie:session-v1:")


@pytest.mark.parametrize(
    "eventid,action,outcome,username,command",
    [
        ("cowrie.session.params", "observed", None, None, None),
        ("cowrie.session.connect", "observed", None, None, None),
        ("cowrie.session.closed", "observed", None, None, None),
        ("cowrie.login.success", "login", "success", "unit-user", None),
        ("cowrie.login.failed", "login", "failure", "unit-user", None),
        ("cowrie.command.input", "command", None, None, "echo synthetic-command"),
    ],
)
def test_six_supported_types_have_literal_mapping(eventid, action, outcome, username, command):
    result = parse(raw_document(eventid=eventid))
    assert result.event.event_action == action
    assert result.event.username == username
    assert result.event.command_line == command
    assert result.provenance.source_event_type == eventid
    assert result.provenance.authentication_outcome == outcome


def test_common_peer_and_source_metadata_mapping_preserves_source_facts():
    result = parse(raw_document())
    event, provenance = result.event, result.provenance
    assert str(event.src_ip) == "192.0.2.20"
    assert event.src_port == 54321
    assert str(event.dst_ip) == "2001:db8::10"
    assert event.dst_port == 22
    assert event.protocol == "ssh"
    assert event.source_record_id == "unit-alert-001"
    assert provenance.source_sensor == "source-sensor"
    assert provenance.source_uuid == "source-uuid"
    assert provenance.arch == "amd64"
    assert provenance.source_fraction_digits == 6
    assert provenance.wazuh_timestamp.isoformat() == "2026-01-02T03:04:06.123Z"
    assert provenance.wazuh_rule_id == "55001"
    assert provenance.wazuh_rule_level == 3
    assert provenance.collector_agent_id == "001"
    assert provenance.collector_agent_name == "unit-agent"
    assert provenance.collector_agent_ip == "192.0.2.10"
    assert provenance.collector_manager_name == "unit-manager"


def test_synthetic_session_sequence_correlates_without_collapsing_events():
    eventids = [
        "cowrie.session.connect",
        "cowrie.login.success",
        "cowrie.command.input",
        "cowrie.session.closed",
    ]
    results = [
        parse(raw_document(eventid=eventid), source_ref=f"unit-{index}.json")
        for index, eventid in enumerate(eventids, 1)
    ]
    assert {result.provenance.session_key for result in results} == {
        "cowrie:session-v1:535c426f129b403f0a313eb161bdcfe8d133a3b90b719f3b7701b30b3802a989"
    }
    assert len({result.event.event_id for result in results}) == 4


def test_session_namespace_isolated_by_sensor_and_environment():
    raw = raw_document()
    original = parse(raw).provenance.session_key
    other_sensor = parse(raw, sensor_id="other-honeypot").provenance.session_key
    other_environment = parse(raw, environment_id="other-lab").provenance.session_key
    assert len({original, other_sensor, other_environment}) == 3


def test_session_key_ignores_evidence_and_ingestion_identity_but_not_uuid_semantics():
    first = parse(raw_document(data={"uuid": "uuid-one"}))
    second = parse(
        raw_document(data={"uuid": "uuid-two"}),
        source_ref="different.json",
        ingested_at="2026-02-03T04:05:06Z",
    )
    assert first.provenance.session_key == second.provenance.session_key
    assert first.event.event_id != second.event.event_id
    assert first.provenance.source_uuid == "uuid-one"
    assert second.provenance.source_uuid == "uuid-two"


@pytest.mark.parametrize("session", [None, _MISSING])
def test_missing_or_null_session_stays_null(session):
    provenance = parse(raw_document(session=session)).provenance
    assert provenance.session is None
    assert provenance.session_key is None


@pytest.mark.parametrize("session", ["", " ", "\t", "\n", 1, True, [], {}])
def test_present_session_must_be_nonblank_text(session):
    with pytest.raises(Exception) as caught:
        parse(raw_document(session=session))
    assert caught.value.code == "invalid_field"
    assert caught.value.field_path == "_source.data.session"


@pytest.mark.parametrize(
    "value,want", [(0, 0), ("0", 0), ("00080", 80), (65535, 65535), ("65535", 65535)]
)
def test_port_boundaries_accept_strict_ints_and_ascii_decimal_strings(value, want):
    assert parse(raw_document(data={"src_port": value})).event.src_port == want


@pytest.mark.parametrize(
    "value",
    [True, False, -1, 65536, "65536", 1.0, "1.0", "1e1", "+1", " 1", "1 ", "١", "", "0" * 129, [], {}],
)
def test_invalid_ports_are_not_coerced(value):
    with pytest.raises(Exception) as caught:
        parse(raw_document(data={"src_port": value}))
    assert caught.value.code == "invalid_field"
    assert caught.value.field_path == "_source.data.src_port"


@pytest.mark.parametrize("value", ["0.0.0.0", "192.0.2.5", "2001:db8::1"])
def test_unscoped_ip_text_is_accepted(value):
    assert str(parse(raw_document(data={"src_ip": value})).event.src_ip) == value


@pytest.mark.parametrize(
    "value", [True, 123, "", "1.2.3.999", "192.0.2.1/24", " 192.0.2.1", "fe80::1%eth0", []]
)
def test_non_text_invalid_or_scoped_addresses_are_rejected(value):
    with pytest.raises(Exception) as caught:
        parse(raw_document(data={"src_ip": value}))
    assert caught.value.code == "invalid_field"
    assert caught.value.field_path == "_source.data.src_ip"


@pytest.mark.parametrize("value", [None, "ssh", "telnet"])
def test_protocol_allowlist(value):
    assert parse(raw_document(data={"protocol": value})).event.protocol == value


@pytest.mark.parametrize("value", ["SSH", "tcp", "", 22, True, []])
def test_protocol_outside_profile_is_rejected(value):
    with pytest.raises(Exception) as caught:
        parse(raw_document(data={"protocol": value}))
    assert caught.value.code == "invalid_field"
    assert caught.value.field_path == "_source.data.protocol"


@pytest.mark.parametrize(
    "wire,want,digits",
    [
        ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z", 0),
        ("2026-01-02T03:04:05.123456+0000", "2026-01-02T03:04:05.123456Z", 6),
        ("2026-01-02T03:04:05.123456789-0700", "2026-01-02T10:04:05.123456789Z", 9),
        ("2026-01-02T03:04:05+07:30", "2026-01-01T19:34:05Z", 0),
    ],
)
def test_source_time_precision_and_zone_forms(wire, want, digits):
    result = parse(raw_document(data={"timestamp": wire}))
    assert result.event.timestamp.isoformat() == want
    assert result.provenance.source_fraction_digits == digits


@pytest.mark.parametrize(
    "value",
    [None, _MISSING, "", "bad", 1, True, "2026-01-02T03:04:05", "2026-02-30T00:00:00Z", "2026-01-01T00:00:00-0000", "2026-01-01T00:00:00.1234567890Z"],
)
def test_invalid_source_time_never_falls_back_to_wazuh_time(value):
    with pytest.raises(Exception) as caught:
        parse(raw_document(data={"timestamp": value}))
    assert caught.value.code == ("missing_event_time" if value in (None, _MISSING) else "invalid_event_time")
    assert caught.value.field_path == "_source.data.timestamp"


def test_data_fields_never_fall_back_to_full_log_or_collector_metadata():
    raw = raw_document(
        eventid="cowrie.login.success",
        data={"username": _MISSING, "src_ip": _MISSING, "sensor": _MISSING},
    )
    document = json.loads(raw)
    document["_source"]["full_log"] = json.dumps(
        {"username": "fallback-user", "src_ip": "198.51.100.4", "sensor": "fallback-sensor"}
    )
    document["_source"]["agent"]["name"] = "fallback-agent"
    result = parse(json.dumps(document, separators=(",", ":")).encode())
    assert result.event.username is None
    assert result.event.src_ip is None
    assert result.provenance.source_sensor is None


def test_unknown_and_credential_fields_remain_raw_only():
    result = parse(raw_document(data={"unknown_private": "raw-only"}))
    result_dump = result.model_dump(mode="json")
    assert "password" not in result_dump
    assert "message" not in result_dump
    assert "unknown_private" not in result_dump
    assert "synthetic-credential-only" not in result.model_dump_json()


@pytest.mark.parametrize(
    "eventid,path,value",
    [
        ("cowrie.login.success", "username", 1),
        ("cowrie.command.input", "input", []),
        ("cowrie.session.params", "username", 1),
        ("cowrie.login.failed", "input", []),
        ("cowrie.session.params", "sensor", True),
        ("cowrie.session.params", "uuid", {}),
        ("cowrie.session.params", "arch", 3),
    ],
)
def test_wrong_present_mapped_text_types_fail(eventid, path, value):
    with pytest.raises(Exception) as caught:
        parse(raw_document(eventid=eventid, data={path: value}))
    assert caught.value.code == "invalid_field"
    assert caught.value.field_path == f"_source.data.{path}"


@pytest.mark.parametrize("eventid", [None, _MISSING])
def test_eventid_is_required(eventid):
    with pytest.raises(Exception) as caught:
        parse(raw_document(data={"eventid": eventid}))
    assert caught.value.code == "missing_field"
    assert caught.value.field_path == "_source.data.eventid"


@pytest.mark.parametrize("eventid", [1, True, [], "cowrie.client.version", "suricata.alert"])
def test_invalid_or_unsupported_eventid_fails_closed(eventid):
    with pytest.raises(Exception) as caught:
        parse(raw_document(data={"eventid": eventid}))
    assert caught.value.code == ("invalid_field" if not isinstance(eventid, str) else "unsupported_profile")
    assert caught.value.field_path == "_source.data.eventid"
