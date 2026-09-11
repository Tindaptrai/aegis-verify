"""Synthetic native Cowrie JSONL tests; no payload here is lab evidence."""

from hashlib import sha256
import json

import pytest


CONTEXT = {
    "source_ref": "unit-native.jsonl",
    "environment_id": "unit-lab",
    "sensor_id": "unit-honeypot",
    "ingested_at": "2026-01-02T03:05:00Z",
}
BASE = {
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
MISSING = object()


def encode(changes=None, *, ending=b"\n"):
    data = BASE.copy()
    for key, value in (changes or {}).items():
        if value is MISSING:
            data.pop(key, None)
        else:
            data[key] = value
    return json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode() + ending


def parse(raw, **changes):
    import aegis_verify.connectors.cowrie as cowrie

    return cowrie.parse_cowrie_jsonl(raw, **(CONTEXT | changes))


def test_native_api_is_available():
    import aegis_verify.connectors.cowrie as cowrie

    assert callable(getattr(cowrie, "parse_cowrie_jsonl", None))


@pytest.mark.parametrize(
    "kind,action,outcome,username,command",
    [
        ("cowrie.session.params", "observed", None, None, None),
        ("cowrie.session.connect", "observed", None, None, None),
        ("cowrie.session.closed", "observed", None, None, None),
        ("cowrie.login.success", "login", "success", "unit-user", None),
        ("cowrie.login.failed", "login", "failure", "unit-user", None),
        ("cowrie.command.input", "command", None, None, "echo synthetic-command"),
    ],
)
def test_six_supported_kinds_have_literal_native_mapping(
    kind, action, outcome, username, command
):
    record, = parse(encode({"eventid": kind}))
    event, provenance = record.event, record.provenance
    assert record.status == "parsed" and record.reason is None
    assert event.event_action == action
    assert event.username == username
    assert event.command_line == command
    assert event.source_record_id is None
    assert provenance.source_event_type == kind
    assert provenance.authentication_outcome == outcome
    assert provenance.mapping_version == "cowrie-native-v1"
    assert provenance.input_profile == "cowrie-jsonl-v1"
    assert provenance.payload_basis == "cowrie.native"
    assert provenance.timestamp_basis == "cowrie.timestamp"


def test_native_maps_source_facts_without_password_or_unknown_enrichment():
    hostile = "DO-NOT-ECHO-UNKNOWN"
    raw = encode({"password": hostile, "unknown": hostile})
    record, = parse(raw)
    event, provenance = record.event, record.provenance
    assert (str(event.src_ip), event.src_port) == ("192.0.2.20", 54321)
    assert (str(event.dst_ip), event.dst_port, event.protocol) == (
        "2001:db8::10", 22, "ssh"
    )
    assert provenance.source_sensor == "source-sensor"
    assert provenance.source_uuid == "source-uuid"
    assert provenance.arch == "amd64"
    assert hostile not in event.model_dump_json()
    assert hostile not in provenance.model_dump_json()


@pytest.mark.parametrize("value", [None, MISSING])
def test_missing_or_null_optional_native_fields_stay_null(value):
    record, = parse(encode({
        "session": value, "sensor": value, "uuid": value, "arch": value,
        "src_ip": value, "src_port": value, "dst_ip": value,
        "dst_port": value, "protocol": value,
    }))
    event, provenance = record.event, record.provenance
    assert (event.src_ip, event.src_port, event.dst_ip, event.dst_port, event.protocol) == (
        None, None, None, None, None
    )
    assert (provenance.session, provenance.session_key) == (None, None)
    assert (provenance.source_sensor, provenance.source_uuid, provenance.arch) == (
        None, None, None
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("session", True), ("session", " "), ("sensor", 1), ("uuid", []),
        ("arch", {}), ("src_ip", "192.0.2.1/24"), ("src_ip", True),
        ("src_port", True), ("src_port", 1.0), ("src_port", "1e1"),
        ("src_port", 65536), ("dst_port", -1), ("protocol", "SSH"),
        ("protocol", 22),
    ],
)
def test_native_mapped_values_are_strict_and_report_direct_paths(field, value):
    import aegis_verify.connectors.cowrie as cowrie

    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(encode({field: value}))
    assert caught.value.code == "invalid_field"
    assert caught.value.field_path == field
    assert caught.value.line == caught.value.record_index == 1


@pytest.mark.parametrize("value,want", [(0, 0), ("00080", 80), (65535, 65535)])
def test_native_port_boundaries(value, want):
    record, = parse(encode({"src_port": value}))
    assert record.event.src_port == want


@pytest.mark.parametrize(
    "wire,want,digits",
    [
        ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z", 0),
        ("2026-01-02T03:04:05.1+0000", "2026-01-02T03:04:05.1Z", 1),
        ("2026-01-02T03:04:05.123456789-0700", "2026-01-02T10:04:05.123456789Z", 9),
        ("2026-01-02T03:04:05+07:30", "2026-01-01T19:34:05Z", 0),
    ],
)
def test_native_timestamp_preserves_precision_and_explicit_zone(wire, want, digits):
    record, = parse(encode({"timestamp": wire}))
    assert record.event.timestamp.isoformat() == want
    assert record.provenance.source_fraction_digits == digits


@pytest.mark.parametrize("digits", range(10))
def test_native_timestamp_accepts_every_supported_fraction_width(digits):
    fraction = "." + "123456789"[:digits] if digits else ""
    record, = parse(encode({"timestamp": f"2026-01-02T03:04:05{fraction}+0000"}))
    assert record.event.timestamp.isoformat() == f"2026-01-02T03:04:05{fraction}Z"
    assert record.provenance.source_fraction_digits == digits


@pytest.mark.parametrize(
    "value,code",
    [
        (None, "missing_event_time"), (MISSING, "missing_event_time"),
        (1, "invalid_event_time"), ("bad", "invalid_event_time"),
        ("2026-01-02T03:04:05", "invalid_event_time"),
        ("2026-01-02T03:04:05.1234567890Z", "invalid_event_time"),
        ("2026-01-02T03:04:05-0000", "invalid_event_time"),
    ],
)
def test_native_timestamp_never_guesses_or_truncates(value, code):
    import aegis_verify.connectors.cowrie as cowrie

    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(encode({"timestamp": value}))
    assert caught.value.code == code
    assert caught.value.field_path == "timestamp"


def test_native_identity_is_exact_and_session_matches_wazuh_profile():
    import aegis_verify.connectors.cowrie as cowrie

    raw = encode()
    native, = parse(raw)
    wazuh_data = BASE.copy()
    wazuh = {"_source": {
        "id": "unit-alert-001",
        "rule": {"id": "55001", "level": 3, "groups": ["cowrie"]},
        "data": wazuh_data,
    }}
    wazuh_raw = json.dumps(wazuh, ensure_ascii=True, separators=(",", ":")).encode()
    wrapped = cowrie.parse_cowrie_wazuh_document(wazuh_raw, **CONTEXT)
    assert native.event.event_id == "cowrie:native-evidence-v1:8d26589b9b1e72ad715698dac0b58c3547168df8483acb9abfb4883a53218d3f"
    assert native.event.event_id == native.provenance.event_id
    assert native.event.raw_event_hash == sha256(raw).hexdigest()
    assert native.event.raw_event_ref == "unit-native.jsonl#L1-L1"
    assert native.provenance.session_key == wrapped.provenance.session_key
    assert native.event.event_id != wrapped.event.event_id


def test_native_identity_changes_with_line_bytes_coordinates_and_context_not_ingestion():
    first, = parse(encode())
    assert parse(encode(), ingested_at="2027-01-01T00:00:00Z")[0].event.event_id == first.event.event_id
    for changes in (
        {"source_ref": "other.jsonl"}, {"environment_id": "other-lab"},
        {"sensor_id": "other-sensor"},
    ):
        assert parse(encode(), **changes)[0].event.event_id != first.event.event_id
    for raw in (encode(ending=b""), encode(ending=b"\r\n"), b"\xef\xbb\xbf" + encode()):
        assert parse(raw)[0].event.event_id != first.event.event_id
    two = parse(encode() + encode())
    assert two[0].event.raw_event_hash == two[1].event.raw_event_hash
    assert two[0].event.event_id != two[1].event.event_id


def test_native_never_enriches_session_neighbors():
    records = parse(
        encode({"eventid": "cowrie.session.connect"})
        + encode({"eventid": "cowrie.command.input", "session": MISSING,
                  "src_ip": MISSING, "sensor": MISSING})
    )
    assert records[0].provenance.session_key is not None
    assert records[1].provenance.session is records[1].provenance.session_key is None
    assert records[1].event.src_ip is None
    assert records[1].provenance.source_sensor is None


def test_physical_framing_preserves_lf_crlf_final_line_bom_and_skips():
    unsupported = json.dumps({"eventid": "cowrie.client.size", "secret": "kept-local"},
                             separators=(",", ":")).encode() + b"\r\n"
    raw = b"\xef\xbb\xbf" + encode() + b" \t\r\n" + unsupported + encode(ending=b"")
    records = parse(raw)
    assert [record.status for record in records] == ["parsed", "skipped", "skipped", "parsed"]
    assert [record.reason for record in records] == [None, "blank_line", "unsupported_event_type", None]
    assert [record.provenance.record_index for record in records] == [1, 2, 3, 4]
    assert records[1].provenance.source_event_type is None
    assert records[2].provenance.source_event_type == "cowrie.client.size"
    assert records[2].provenance.timestamp_basis is None
    assert records[2].provenance.source_fraction_digits is None
    assert records[3].event.raw_event_ref == "unit-native.jsonl#L4-L4"
    assert records[0].event.raw_event_hash == sha256(b"\xef\xbb\xbf" + encode()).hexdigest()
    assert records[1].provenance.raw_event_hash == sha256(b" \t\r\n").hexdigest()
    assert parse(b"") == ()


@pytest.mark.parametrize(
    "value",
    [None, True, 1, [], "", "cowrie", "Cowrie.login.failed", "cowrie.Login",
     "cowrie.login-failed", "cowrie..login", "cowrie.login.", "cowrie.a" + "a" * 122],
)
def test_invalid_native_event_selector_is_an_error(value):
    import aegis_verify.connectors.cowrie as cowrie

    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(encode({"eventid": value}))
    assert caught.value.code == "invalid_field"
    assert caught.value.field_path == "eventid"


@pytest.mark.parametrize(
    "tail,code",
    [
        (b"{\n", "invalid_json"),
        (b"[]\n", "invalid_root"),
        (b'{"eventid":"cowrie.client.size","x":1,"x":2}\n', "duplicate_key"),
        (b'{"eventid":"cowrie.client.size","x":{"a":1,"a":2}}\n', "duplicate_key"),
        (b'{"eventid":"cowrie.client.size","x":NaN}\n', "invalid_number"),
        (b'{"eventid":"cowrie.client.size","x":"\\ud800"}\n', "invalid_unicode"),
        (b"\xff\n", "invalid_encoding"),
        (b"\xef\xbb\xbf{}\n", "invalid_bom"),
        (b'{"eventid":"cowrie.client.size","x":"\xef\xbb\xbf"}\n', "invalid_bom"),
    ],
)
def test_late_native_errors_are_strict_sanitized_and_physical(tail, code):
    import aegis_verify.connectors.cowrie as cowrie

    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(encode() + tail)
    diagnostic = caught.value.diagnostic
    assert diagnostic.code == code
    assert diagnostic.line == diagnostic.record_index == 2
    assert "client.size" not in str(caught.value)
    assert caught.value.__suppress_context__


def test_json_error_column_is_retained_but_line_is_physical_record():
    import aegis_verify.connectors.cowrie as cowrie

    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(b"\n  {\n")
    assert caught.value.code == "invalid_json"
    assert caught.value.line == caught.value.record_index == 2
    assert caught.value.column == 1


def test_unsupported_kinds_are_json_validated_only():
    raw = json.dumps({
        "eventid": "cowrie.client.size", "timestamp": True, "src_port": 999999,
        "password": "not-copied",
    }, separators=(",", ":")).encode() + b"\n"
    record, = parse(raw)
    assert record.status == "skipped" and record.reason == "unsupported_event_type"
    assert record.event is None
    assert record.provenance.session is record.provenance.authentication_outcome is None


@pytest.mark.parametrize(
    "raw,code",
    [
        (b'{"eventid":"cowrie.client.size","x":' + b"[" * 20 + b"0" + b"]" * 20 + b"}\n", "max_depth"),
        (b'{"eventid":"cowrie.client.size","x":' + b"9" * 129 + b"}\n", "invalid_number"),
        (b'{"eventid":"cowrie.client.size","x":[' + b"0," * 9999 + b"0]}\n", "max_nodes"),
    ],
)
def test_native_strict_json_budgets_apply_to_unsupported_kinds(raw, code):
    import aegis_verify.connectors.cowrie as cowrie

    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(raw)
    assert caught.value.code == code


def test_native_strict_json_budget_boundaries_are_accepted():
    cases = [
        b'{"eventid":"cowrie.client.size","x":' + b"[" * 19 + b"0" + b"]" * 19 + b"}\n",
        b'{"eventid":"cowrie.client.size","x":' + b"9" * 128 + b"}\n",
        b'{"eventid":"cowrie.client.size","x":[' + b"0," * 9996 + b"0]}\n",
    ]
    assert [parse(raw)[0].reason for raw in cases] == [
        "unsupported_event_type", "unsupported_event_type", "unsupported_event_type"
    ]


def test_native_line_total_and_count_limits_are_exact(tmp_path):
    import aegis_verify.connectors.cowrie as cowrie

    exact_line = b" " * (256 * 1024 - 1) + b"\n"
    record, = parse(exact_line)
    assert record.reason == "blank_line"
    assert record.provenance.raw_event_hash == sha256(exact_line).hexdigest()
    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(b" " * (256 * 1024) + b"\n")
    assert caught.value.code == "input_too_large"
    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(b" " * (32 * 1024 * 1024 + 1))
    assert caught.value.code == "total_input_too_large"
    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(b"\n" * 100001)
    assert caught.value.code == "max_records"
    assert caught.value.line == caught.value.record_index == 100001
    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse("{}")
    assert caught.value.code == "input_type"

    path = tmp_path / "total.jsonl"
    with path.open("wb") as stream:
        for _ in range(128):
            stream.write(exact_line)
        stream.write(b"\n")
    iterator = cowrie.iter_cowrie_file(path, **CONTEXT)
    for index in range(1, 129):
        assert next(iterator).provenance.record_index == index
    with pytest.raises(cowrie.CowrieParseError) as caught:
        next(iterator)
    assert caught.value.code == "total_input_too_large"
    assert caught.value.line == caught.value.record_index == 129


def test_native_file_iterator_yields_before_late_error_and_releases_file(tmp_path):
    import aegis_verify.connectors.cowrie as cowrie

    path = tmp_path / "native.jsonl"
    path.write_bytes(encode() + b"{\n")
    iterator = cowrie.iter_cowrie_file(path, **CONTEXT)
    assert next(iterator).status == "parsed"
    with pytest.raises(cowrie.CowrieParseError) as caught:
        next(iterator)
    assert caught.value.code == "invalid_json" and caught.value.line == 2
    path.rename(tmp_path / "renamed.jsonl")

    path.write_bytes(encode() + encode({"eventid": "cowrie.client.size"}))
    assert tuple(cowrie.iter_cowrie_file(path, **CONTEXT)) == parse(path.read_bytes())
    iterator = cowrie.iter_cowrie_file(path, **CONTEXT)
    next(iterator)
    iterator.close()
    path.unlink()


def test_native_file_record_limit_counts_skipped_lines(tmp_path):
    import aegis_verify.connectors.cowrie as cowrie

    path = tmp_path / "many-lines.jsonl"
    path.write_bytes(b"\n" * 100001)
    iterator = cowrie.iter_cowrie_file(path, **CONTEXT)
    last = None
    with pytest.raises(cowrie.CowrieParseError) as caught:
        for last in iterator:
            pass
    assert last.provenance.record_index == 100000
    assert caught.value.code == "max_records"
    assert caught.value.line == caught.value.record_index == 100001


def test_native_file_errors_are_sanitized_and_context_precedes_open(tmp_path):
    import aegis_verify.connectors.cowrie as cowrie

    for path in (tmp_path / "SECRET", 0, None):
        with pytest.raises(cowrie.CowrieParseError) as caught:
            tuple(cowrie.iter_cowrie_file(path, **CONTEXT))
        assert caught.value.code == "io_error"
        assert "SECRET" not in str(caught.value)
    with pytest.raises(cowrie.CowrieParseError) as caught:
        tuple(cowrie.iter_cowrie_file(tmp_path / "SECRET", **(CONTEXT | {"sensor_id": "../bad"})))
    assert caught.value.code == "invalid_context"


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_ref", "../secret"), ("source_ref", "x\n"),
        ("sensor_id", ""), ("sensor_id", []), ("sensor_id", "x" * 129),
        ("environment_id", " "), ("environment_id", "é" * 65),
        ("ingested_at", "2026-01-01"),
    ],
)
def test_native_context_is_explicit_and_strict(field, value):
    import aegis_verify.connectors.cowrie as cowrie

    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(encode(), **{field: value})
    assert caught.value.code == "invalid_context"
    assert caught.value.field_path == field


def test_native_bytes_api_is_atomic_on_mixed_input():
    import aegis_verify.connectors.cowrie as cowrie

    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(encode() + encode({"eventid": "cowrie.client.size"}) + b"{\n")
    assert caught.value.line == caught.value.record_index == 3


def test_lone_cr_does_not_create_a_second_native_record():
    import aegis_verify.connectors.cowrie as cowrie

    with pytest.raises(cowrie.CowrieParseError) as caught:
        parse(encode(ending=b"") + b"\r" + encode())
    assert caught.value.code == "invalid_json"
    assert caught.value.line == caught.value.record_index == 1


def test_native_records_and_provenance_are_immutable():
    record, = parse(encode())
    skipped, = parse(b"\n")
    with pytest.raises(ValueError):
        record.status = "skipped"
    with pytest.raises(ValueError):
        skipped.provenance.raw_event_hash = "0" * 64


def test_native_provenance_rejects_invalid_coordinates_and_relationships():
    from aegis_verify.connectors.cowrie import CowrieNativeProvenance

    parsed, = parse(encode())
    base = parsed.provenance.model_dump()
    mutations = [
        {"record_index": True}, {"line_start": 1.0}, {"line_end": 2},
        {"raw_event_hash": "0" * 64}, {"raw_event_ref": "unit-native.jsonl#L2-L2"},
        {"event_id": "cowrie:native-evidence-v1:" + "0" * 64},
        {"session_key": None}, {"authentication_outcome": "success"},
        {"source_fraction_digits": 10}, {"timestamp_basis": None},
    ]
    for changes in mutations:
        with pytest.raises(ValueError):
            CowrieNativeProvenance.model_validate(base | changes)


def test_native_record_rejects_contradictory_outcomes_and_event_identity():
    from aegis_verify.connectors.cowrie import CowrieNativeRecord

    parsed, = parse(encode())
    skipped, = parse(b"\n")
    cases = [
        {"status": "skipped", "reason": None, "event": parsed.event,
         "provenance": parsed.provenance},
        {"status": "parsed", "reason": "blank_line", "event": parsed.event,
         "provenance": parsed.provenance},
        {"status": "parsed", "reason": None, "event": None,
         "provenance": parsed.provenance},
        {"status": "parsed", "reason": None, "event": parsed.event,
         "provenance": skipped.provenance},
        {"status": "skipped", "reason": "blank_line", "event": parsed.event,
         "provenance": skipped.provenance},
    ]
    for data in cases:
        with pytest.raises(ValueError):
            CowrieNativeRecord.model_validate(data)

    for changes in (
        {"event_id": "cowrie:changed"},
        {"raw_event_hash": "0" * 64},
        {"raw_event_ref": "unit-native.jsonl#L2-L2"},
        {"environment_id": "other-lab"},
        {"source_record_id": "source-uuid"},
    ):
        changed_event = parsed.event.model_copy(update=changes)
        with pytest.raises(ValueError):
            CowrieNativeRecord(
                status="parsed", event=changed_event, provenance=parsed.provenance
            )


def test_native_record_rejects_action_and_precision_contradictions():
    from aegis_verify.connectors.cowrie import CowrieNativeRecord
    from aegis_verify.models import PreciseTimestamp

    parsed, = parse(encode())
    for changes in (
        {"event_action": "command"},
        {"timestamp": PreciseTimestamp.parse("2026-01-02T03:04:05.123Z")},
    ):
        with pytest.raises(ValueError):
            CowrieNativeRecord(
                status="parsed",
                event=parsed.event.model_copy(update=changes),
                provenance=parsed.provenance,
            )
