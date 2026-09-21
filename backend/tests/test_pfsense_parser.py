"""Synthetic ingestion cases; none of these records are lab evidence."""

from hashlib import sha256
from io import BytesIO
import json
import traceback

import pytest

import aegis_verify.connectors.pfsense as pfsense
from aegis_verify.models import CanonicalEventV2


SYNTHETIC_PASS = (
    b"Sep 10 21:01:41 fixture-fw filterlog[1]: "
    b"4,,,1000000001,fixture0,match,pass,in,4,0x0,,64,1,0,none,17,udp,"
    b"69,192.0.2.1,198.51.100.1,5353,5353,49"
)
BOM = b"\xef\xbb\xbf"


@pytest.fixture
def kwargs():
    return dict(source_ref="unit-log", environment_id="unit-env", sensor_id="unit-fw",
                ingested_at="2026-09-10T15:00:00Z", source_year=2026,
                source_utc_offset="+07:00")


def parse(raw, kwargs):
    return pfsense.parse_pfsense_filterlog(raw, **kwargs)


@pytest.mark.parametrize("program", [b"filterlog", b"filterlog[1]"])
@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
def test_hostname_less_syslog_preserves_missing_host_and_exact_bytes(kwargs, program, ending):
    raw = SYNTHETIC_PASS.replace(b"fixture-fw filterlog[1]", program) + ending
    record = parse(raw, kwargs)[0]
    assert record.status == "parsed"
    assert record.event.hostname is None
    assert record.provenance.sensor_id == "unit-fw"
    assert record.event.raw_event_hash == sha256(raw).hexdigest()
    assert record.event.timestamp.isoformat() == "2026-09-10T14:01:41Z"
    assert record.event.event_action == "allowed"
    assert record.event.protocol == "udp"
    assert record.event.src_port == 5353
    assert record.event.dst_port == 5353
    assert record.event.rule_id == "1000000001"
    assert record == parse(raw, kwargs)[0]


def test_sensor_label_never_becomes_missing_hostname(kwargs):
    raw = SYNTHETIC_PASS.replace(b"fixture-fw ", b"")
    first = parse(raw, kwargs)[0]
    second = parse(raw, kwargs | {"sensor_id": "configured-firewall"})[0]
    assert first.event.hostname is second.event.hostname is None
    assert second.provenance.sensor_id == "configured-firewall"
    assert first.event.raw_event_hash == second.event.raw_event_hash
    assert first.event.event_id != second.event.event_id


def test_exact_bytes_identity_and_valid_canonical(kwargs):
    raw = SYNTHETIC_PASS + b"\r\n"
    record = parse(raw, kwargs)[0]
    assert record == parse(raw, kwargs)[0]
    event = record.event
    assert event.schema_version == "2.0"
    assert event.raw_event_hash == sha256(raw).hexdigest()
    assert event.raw_event_ref == "unit-log#L1-L1"
    identity = ["pfsense-filterlog-evidence-v1", "unit-env", "unit-fw", "unit-log",
                1, sha256(raw).hexdigest(), 2026, "+07:00"]
    digest = sha256(json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
    assert event.event_id == "pfsense:filterlog-evidence-v1:" + digest
    assert CanonicalEventV2.model_validate_json(event.model_dump_json()) == event
    assert record.provenance.event_id == event.event_id
    assert record.provenance.raw_event_hash == event.raw_event_hash
    assert record.provenance.raw_event_ref == event.raw_event_ref
    assert event.timestamp.isoformat() == "2026-09-10T14:01:41Z"
    assert event.environment_id == "unit-env"
    assert event.event_action == "allowed"
    assert event.source_record_id is None
    assert record.provenance.interface == "fixture0"
    assert record.provenance.source_year == 2026
    assert record.provenance.source_utc_offset == "+07:00"
    assert record.provenance.timestamp_basis == "bsd_syslog_with_caller_context"
    assert record.provenance.warnings == ("year_and_offset_supplied_by_caller",)
    assert record.provenance.nat_context is None


@pytest.mark.parametrize("key,value", [("environment_id", "other-env"),
    ("environment_id", "môi-trường"), ("sensor_id", "other-fw"),
    ("source_ref", "other-log"), ("source_year", 2025), ("source_utc_offset", "+08:00")])
def test_identity_changes_with_evidence_context(kwargs, key, value):
    first = parse(SYNTHETIC_PASS, kwargs)[0]
    other = parse(SYNTHETIC_PASS, kwargs | {key: value})[0]
    assert first.event.event_id != other.event.event_id


def test_ingestion_time_replay_preserves_identity(kwargs):
    first = parse(SYNTHETIC_PASS, kwargs)[0]
    other = parse(SYNTHETIC_PASS, kwargs | {"ingested_at": "2026-09-11T15:00:00Z"})[0]
    assert first.event.event_id == other.event.event_id
    assert first.event.ingested_at != other.event.ingested_at


def test_duplicate_physical_lines_have_distinct_identity(kwargs):
    raw = SYNTHETIC_PASS + b"\n"
    first, blank, third = parse(raw + b"\n" + raw, kwargs)
    assert first.event.raw_event_hash == third.event.raw_event_hash
    assert first.event.event_id != third.event.event_id
    assert blank.provenance.line_start == 2
    assert third.event.raw_event_ref == "unit-log#L3-L3"
    assert third.provenance.record_index == third.provenance.line_end == 3


def test_byte_variants_change_hash_and_identity_but_not_mapping(kwargs):
    inputs = [SYNTHETIC_PASS, SYNTHETIC_PASS + b"\n", SYNTHETIC_PASS + b"\r\n",
              BOM + SYNTHETIC_PASS + b"\n"]
    events = [parse(raw, kwargs)[0].event for raw in inputs]
    assert len({event.event_id for event in events}) == 4
    assert len({event.raw_event_hash for event in events}) == 4
    assert {event.timestamp.isoformat() for event in events} == {"2026-09-10T14:01:41Z"}
    for raw, event in zip(inputs, events):
        assert event.raw_event_hash == sha256(raw).hexdigest()


@pytest.mark.parametrize("raw,count", [(b"", 0), (b"\n", 1), (b" \r\n", 1),
    (BOM, 1), (BOM + b"\n\n", 2)])
def test_empty_and_blank_outcomes_preserve_context(kwargs, raw, count):
    records = parse(raw, kwargs)
    assert isinstance(records, tuple)
    assert len(records) == count
    for record in records:
        assert record.status == "skipped"
        assert record.reason == "blank_line"
        assert record.event is record.provenance.event_id is None
        assert record.provenance.source_year == 2026
        assert record.provenance.source_utc_offset == "+07:00"


def test_skip_only_input_has_auditable_outcomes(kwargs):
    rotation = b"Sep 10 21:01:41 fixture-fw newsyslog: logfile turned over due to size>100K\n"
    ipv6 = SYNTHETIC_PASS.replace(b",in,4,", b",in,6,") + b"\n"
    igmp = SYNTHETIC_PASS.replace(b",17,udp,", b",2,igmp,")
    records = parse(rotation + ipv6 + igmp, kwargs)
    assert [r.reason for r in records] == ["rotation_notice", "unsupported_ip_version", "unsupported_protocol"]
    for index, (record, raw) in enumerate(zip(records, [rotation, ipv6, igmp]), 1):
        assert record.event is record.provenance.event_id is None
        assert record.provenance.raw_event_ref == f"unit-log#L{index}-L{index}"
        assert record.provenance.raw_event_hash == sha256(raw).hexdigest()
        assert record.provenance.warnings == ("year_and_offset_supplied_by_caller",)


@pytest.mark.parametrize("raw,code", [(b"\xff", "invalid_encoding"),
    (SYNTHETIC_PASS + b"\n" + BOM + SYNTHETIC_PASS, "invalid_bom"),
    (SYNTHETIC_PASS + BOM, "invalid_bom"), (BOM + BOM + SYNTHETIC_PASS, "invalid_bom"),
    (b"<34>1 2026-09-10T21:01:41Z fixture-fw filterlog - - - payload", "malformed_header"),
    (b"raw,payload", "malformed_header"), (b"\x00clog", "invalid_field"),
    (SYNTHETIC_PASS + b"\r", "invalid_field"),
    (SYNTHETIC_PASS + b"\r\r\n", "invalid_field"),
    (b"Sep 10 21:01:41 fixture-fw filterSep 10 21:01:41 fixture-fw filterlog: 4", "malformed_header")])
def test_invalid_input_has_safe_positioned_error(kwargs, raw, code):
    with pytest.raises(pfsense.PfSenseParseError) as caught:
        parse(raw, kwargs)
    assert caught.value.code == code
    expected_line = 2 if b"\n" in raw.rstrip(b"\n") else 1
    assert caught.value.line == caught.value.record_index == expected_line
    assert caught.value.__cause__ is None
    assert "fixture-fw" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("raw", [None, "text", bytearray(b""), memoryview(b"")])
def test_bytes_api_rejects_nonbytes(kwargs, raw):
    with pytest.raises(pfsense.PfSenseParseError, match="input_type"):
        parse(raw, kwargs)


@pytest.mark.parametrize("api", ["bytes", "file"])
def test_context_validates_even_empty_input(kwargs, tmp_path, api):
    kwargs["source_year"] = True
    path = tmp_path / "empty.log"
    path.write_bytes(b"")
    with pytest.raises(pfsense.PfSenseParseError) as caught:
        parse(b"", kwargs) if api == "bytes" else tuple(pfsense.iter_pfsense_filterlog_file(path, **kwargs))
    assert caught.value.code == "invalid_context"
    assert caught.value.field_path == "source_year"


@pytest.mark.parametrize("api", ["bytes", "file"])
@pytest.mark.parametrize("budget,raw,limit,code", [
    ("MAX_LINE_BYTES", b"    \n", 5, "input_too_large"),
    ("MAX_FILE_BYTES", b"\n\n\n\n\n", 5, "total_input_too_large"),
    ("MAX_RECORDS", b"\n\n\n\n\n", 5, "max_records"),
])
def test_budget_exact_boundary_and_one_beyond(kwargs, tmp_path, monkeypatch, api, budget, raw, limit, code):
    from aegis_verify.connectors.pfsense import parser
    monkeypatch.setattr(parser, budget, limit)
    path = tmp_path / "bounded.log"
    def run(data):
        if api == "bytes":
            return parse(data, kwargs)
        path.write_bytes(data)
        return tuple(pfsense.iter_pfsense_filterlog_file(path, **kwargs))
    assert run(raw)
    beyond = b" " + raw if budget == "MAX_LINE_BYTES" else raw + b"\n"
    with pytest.raises(pfsense.PfSenseParseError) as caught:
        run(beyond)
    assert caught.value.code == code


def test_real_line_limit_includes_bom_and_newline(kwargs):
    raw = BOM + b" " * (256 * 1024 - 4) + b"\n"
    assert parse(raw, kwargs)[0].reason == "blank_line"
    with pytest.raises(pfsense.PfSenseParseError, match="input_too_large"):
        parse(raw[:-1] + b" \n", kwargs)


@pytest.mark.parametrize("budget", ["MAX_LINE_BYTES", "MAX_FILE_BYTES", "MAX_RECORDS"])
def test_supported_record_boundary_and_late_stream_limit(kwargs, tmp_path, monkeypatch, budget):
    from aegis_verify.connectors.pfsense import parser
    raw = BOM + SYNTHETIC_PASS + b"\r\n"
    monkeypatch.setattr(parser, budget, 1 if budget == "MAX_RECORDS" else len(raw))
    assert parse(raw, kwargs)[0].status == "parsed"
    path = tmp_path / "bounded.log"
    if budget == "MAX_LINE_BYTES":
        # First valid record fits; the next valid-source record exceeds by one byte.
        second = SYNTHETIC_PASS.replace(b"fixture-fw", b"fixture-fw1234") + b"\r\n"
    else:
        second = SYNTHETIC_PASS + b"\n"
    path.write_bytes(raw + second)
    records = pfsense.iter_pfsense_filterlog_file(path, **kwargs)
    assert next(records).status == "parsed"
    with pytest.raises(pfsense.PfSenseParseError) as caught:
        next(records)
    assert caught.value.code == {"MAX_LINE_BYTES": "input_too_large",
        "MAX_FILE_BYTES": "total_input_too_large", "MAX_RECORDS": "max_records"}[budget]
    assert caught.value.line == caught.value.record_index == 2


def test_file_and_bytes_outcomes_match(kwargs, tmp_path):
    raw = BOM + SYNTHETIC_PASS + b"\r\n\n" + SYNTHETIC_PASS
    path = tmp_path / "fixture.log"
    path.write_bytes(raw)
    assert tuple(pfsense.iter_pfsense_filterlog_file(path, **kwargs)) == parse(raw, kwargs)


def test_bytes_failure_is_atomic_and_file_late_failure_is_incomplete(kwargs, tmp_path):
    raw = SYNTHETIC_PASS + b"\nprivate-host malformed"
    path = tmp_path / "fixture.log"
    path.write_bytes(raw)
    returned = None
    with pytest.raises(pfsense.PfSenseParseError):
        returned = parse(raw, kwargs)
    assert returned is None
    stream = pfsense.iter_pfsense_filterlog_file(path, **kwargs)
    assert next(stream).status == "parsed"
    with pytest.raises(pfsense.PfSenseParseError) as caught:
        next(stream)
    assert caught.value.line == caught.value.record_index == 2
    assert caught.value.code == "malformed_header"
    assert "private-host" not in str(caught.value)
    assert list(stream) == []


@pytest.mark.parametrize("path", [None, 1, "private-path\x00secret"])
def test_invalid_file_paths_have_safe_io_error(kwargs, path):
    with pytest.raises(pfsense.PfSenseParseError) as caught:
        tuple(pfsense.iter_pfsense_filterlog_file(path, **kwargs))
    assert caught.value.code == "io_error"
    assert "private-path" not in "".join(traceback.format_exception(caught.value))


def test_missing_file_has_safe_io_error(kwargs, tmp_path):
    path = tmp_path / "private-file"
    with pytest.raises(pfsense.PfSenseParseError) as caught:
        tuple(pfsense.iter_pfsense_filterlog_file(path, **kwargs))
    assert caught.value.code == "io_error"
    assert "private-file" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("finish", ["exhaust", "close", "read_error", "parse_error", "close_error"])
def test_file_reads_are_bounded_and_resources_close(kwargs, monkeypatch, finish):
    from aegis_verify.connectors.pfsense import parser
    class ObservedStream(BytesIO):
        calls = 0
        def readline(self, size=-1):
            assert size == 256 * 1024 + 1
            self.calls += 1
            if finish == "read_error" and self.calls == 2:
                raise OSError("private-device secret")
            return super().readline(size)
        def close(self):
            was_closed = self.closed
            super().close()
            if finish == "close_error" and not was_closed:
                raise OSError("private-close secret")
    raw = SYNTHETIC_PASS + b"\n"
    stream = ObservedStream(raw + (b"bad" if finish == "parse_error" else b""))
    monkeypatch.setattr(parser, "open", lambda *args: stream, raising=False)
    records = pfsense.iter_pfsense_filterlog_file("safe-label", **kwargs)
    assert next(records).status == "parsed"
    if finish == "close":
        records.close()
    elif finish == "exhaust":
        assert list(records) == []
    else:
        with pytest.raises(pfsense.PfSenseParseError) as caught:
            list(records)
        assert caught.value.code == ("malformed_header" if finish == "parse_error" else "io_error")
        assert "secret" not in "".join(traceback.format_exception(caught.value))
        if finish == "read_error":
            assert caught.value.line == 2
    assert stream.closed


def test_canonical_validation_cannot_be_bypassed(kwargs, monkeypatch):
    from aegis_verify.connectors.pfsense import parser
    original = parser.map_filterlog_line
    def invalid_mapping(text, context):
        fields, metadata, reason = original(text, context)
        fields["src_port"] = 65536
        return fields, metadata, reason
    monkeypatch.setattr(parser, "map_filterlog_line", invalid_mapping)
    with pytest.raises(pfsense.PfSenseParseError) as caught:
        parse(SYNTHETIC_PASS, kwargs)
    assert caught.value.code == "canonical_validation"
    assert caught.value.field_path == "canonical.src_port"
    assert caught.value.line == 1
    assert "65536" not in "".join(traceback.format_exception(caught.value))
