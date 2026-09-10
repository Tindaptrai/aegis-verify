"""Synthetic filterlog cases: these records are not lab evidence."""

import pytest

from aegis_verify.connectors.pfsense import PfSenseParseError, PfSenseProvenance, make_context
from aegis_verify.connectors.pfsense._mapping import map_filterlog_line
from aegis_verify.models import CanonicalEventV2


HEADER = "Sep 10 21:01:41 fixture-fw filterlog[1]: "
SYNTHETIC_PASS = (
    HEADER + "4,,,1000000001,fixture0,match,pass,in,4,0x0,,64,1,0,none,17,udp,"
    "69,192.0.2.1,198.51.100.1,5353,5353,49"
)
SYNTHETIC_TCP = (
    HEADER + "4,,,1000000001,fixture0,match,block,out,4,0x0,,64,1,0,DF,6,tcp,"
    "60,192.0.2.1,198.51.100.1,12345,443,0,S,4294967295,0,65535,,"
)


@pytest.fixture
def context():
    return make_context(
        source_ref="synthetic-log", environment_id="unit-env", sensor_id="unit-fw",
        ingested_at="2026-09-10T15:00:00Z", source_year=2026, source_utc_offset="+07:00",
    )


def changed(line=SYNTHETIC_PASS, **cells):
    """Mutate specific source columns while preserving empty cells."""
    payload = line[len(HEADER):].split(",")
    for index, value in cells.items():
        payload[int(index)] = value
    return HEADER + ",".join(payload)


def test_pass_mapping_and_provenance(context):
    fields, metadata, reason = map_filterlog_line(SYNTHETIC_PASS, context)
    assert reason is None
    assert fields == dict(
        source_type="pfsense", event_provider="pfSense-filterlog",
        timestamp=fields["timestamp"], hostname="fixture-fw", event_action="allowed",
        protocol="udp", src_ip="192.0.2.1", dst_ip="198.51.100.1",
        src_port=5353, dst_port=5353, rule_id="1000000001",
    )
    assert fields["timestamp"].isoformat() == "2026-09-10T14:01:41Z"
    provenance = PfSenseProvenance(
        **metadata, source_ref=context.source_ref, sensor_id=context.sensor_id,
        record_index=1, line_start=1, line_end=1, raw_event_hash="a" * 64,
        raw_event_ref="synthetic-log#L1-L1",
    )
    assert provenance.interface == "fixture0"
    assert provenance.direction == "in"
    assert provenance.reason == "match"
    assert provenance.rule_number == "4"
    assert provenance.subrule is None
    assert provenance.anchor is None
    assert provenance.tracker == "1000000001"
    assert provenance.protocol_id == "17"
    assert provenance.protocol_text == "udp"
    assert provenance.timestamp_text == "Sep 10 21:01:41"
    assert provenance.source_year == 2026
    assert provenance.source_utc_offset == "+07:00"
    assert provenance.timestamp_basis == "bsd_syslog_with_caller_context"
    assert provenance.warnings == ("year_and_offset_supplied_by_caller",)
    assert provenance.nat_context is None


@pytest.mark.parametrize("line, protocol", [(SYNTHETIC_TCP, "tcp"), (changed(**{"6": "block"}), "udp")])
def test_block_maps_only_observed_action(context, line, protocol):
    fields, _, reason = map_filterlog_line(line, context)
    assert reason is None
    assert fields["event_action"] == "blocked"
    assert fields["protocol"] == protocol


def test_empty_optional_cells_stay_null_after_canonical_construction(context):
    fields, metadata, _ = map_filterlog_line(
        changed(**{"3": "", "18": "", "19": "", "20": "", "21": ""}), context
    )
    event = CanonicalEventV2(
        **fields, environment_id=context.environment_id, ingested_at=context.ingested_at,
        event_id="pfsense:synthetic", raw_event_hash="a" * 64, raw_event_ref="synthetic-log#L1-L1",
    )
    absent = (
        "src_ip", "dst_ip", "src_port", "dst_port", "rule_id", "asset_id", "username",
        "severity", "source_record_id", "signature_id", "technique_ids", "process_name",
        "process_id", "parent_process_name", "command_line", "file_path", "file_hash",
    )
    assert all(getattr(event, field) is None for field in absent)
    assert metadata["tracker"] is None
    assert metadata["rule_number"] == "4"
    assert metadata["nat_context"] is None


def test_preserves_port_zero_raw_tracker_and_case_insensitive_protocol(context):
    fields, metadata, _ = map_filterlog_line(
        changed(**{"3": "0001", "16": "UDP", "20": "0", "21": "65535"}), context
    )
    assert fields["src_port"] == 0
    assert fields["dst_port"] == 65535
    assert fields["rule_id"] == "0001"
    assert fields["protocol"] == "udp"
    assert metadata["protocol_text"] == "UDP"


@pytest.mark.parametrize("index, token, field", [
    (0, "-1", "rule_number"), (1, "1.0", "subrule"), (3, "x", "tracker"),
    (3, "1" * 129, "tracker"), (4, "", "interface"), (5, "", "reason"),
    (6, "reject", "action"), (7, "sideways", "direction"), (8, "4.0", "ip_version"),
    (9, "0x100", "tos"), (9, "+1", "tos"), (10, "256", "ecn"),
    (11, "256", "ttl"), (12, "65536", "ip_id"), (13, "-1", "offset"),
    (13, "0" * 129, "offset"), (15, "256", "protocol_id"),
    (15, "6", "protocol_text"), (15, "2", "protocol_text"),
    (16, "tcp", "protocol_text"), (16, "igmp", "protocol_text"),
    (17, "65536", "length"), (18, "2001:db8::1", "src_ip"),
    (18, "192.0.2.1/24", "src_ip"), (18, "3221225985", "src_ip"),
    (19, "endpoint.invalid", "dst_ip"), (20, "65536", "src_port"),
    (20, "-1", "src_port"), (20, "+1", "src_port"), (20, "1.0", "src_port"),
    (20, "True", "src_port"), (20, "\u0661", "src_port"), (20, " 1", "src_port"),
    (21, "1" * 129, "dst_port"), (22, "65536", "data_length"),
])
def test_malformed_ipv4_is_error_never_skip(context, index, token, field):
    with pytest.raises(PfSenseParseError) as caught:
        map_filterlog_line(changed(**{str(index): token}), context)
    assert caught.value.field_path == field
    assert caught.value.code in {"invalid_field", "missing_field", "unsupported_value"}
    assert "fixture-fw" not in str(caught.value)
    assert "192.0.2.1" not in str(caught.value)


@pytest.mark.parametrize("index, token", [
    (24, "4294967296"), (24, "1:4294967296"), (24, "1:2:3"), (24, ":1"),
    (24, "-1:2"), (24, "1:"), (24, "1.0"), (24, "1" * 129),
    (25, "4294967296"), (25, "1:2"), (26, "65536"), (27, "65536"),
])
def test_tcp_numeric_tail_is_bounded(context, index, token):
    with pytest.raises(PfSenseParseError) as caught:
        map_filterlog_line(changed(SYNTHETIC_TCP, **{str(index): token}), context)
    assert caught.value.code == "invalid_field"
    assert caught.value.field_path == {24: "sequence", 25: "ack", 26: "window", 27: "urg"}[index]


@pytest.mark.parametrize("sequence", ["0", "4294967295", "1:2", "4294967295:0", "0:0", ""])
def test_tcp_sequence_accepts_uint32_and_wrap_ranges(context, sequence):
    fields, _, reason = map_filterlog_line(changed(SYNTHETIC_TCP, **{"24": sequence}), context)
    assert reason is None
    assert fields["protocol"] == "tcp"


def test_optional_numeric_ip_transport_cells_can_be_empty(context):
    indices = (9, 10, 11, 12, 13, 17, 22, 24, 25, 26, 27)
    fields, _, reason = map_filterlog_line(changed(SYNTHETIC_TCP, **{str(i): "" for i in indices}), context)
    assert reason is None
    assert fields["src_port"] == 12345


def test_numeric_boundaries_and_offset_token_limit(context):
    fields, _, reason = map_filterlog_line(changed(SYNTHETIC_TCP, **{
        "9": "0xff", "10": "0XFF", "11": "255", "12": "65535",
        "13": "9" * 128, "17": "65535", "22": "65535", "25": "4294967295", "27": "65535",
    }), context)
    assert reason is None
    assert fields["protocol"] == "tcp"


@pytest.mark.parametrize("line", [
    SYNTHETIC_PASS.rsplit(",", 1)[0], SYNTHETIC_PASS + ",", SYNTHETIC_TCP[:-1], SYNTHETIC_TCP + ",",
    HEADER + "4,,,1000000001,fixture0,match,pass,in",
])
def test_missing_or_extra_columns_are_not_null(context, line):
    with pytest.raises(PfSenseParseError):
        map_filterlog_line(line, context)


@pytest.mark.parametrize("token", ['"quoted"', "a'b", "bad\nline", "bad\rline", "bad\tcell", "bad\x00cell", "bad\x7fcell", "bad\u0085cell", "bad\ufeffcell"])
def test_embedded_quotes_controls_and_bom_are_rejected(context, token):
    with pytest.raises(PfSenseParseError):
        map_filterlog_line(changed(**{"2": token}), context)


@pytest.mark.parametrize("separator", ["\u2028", "\u2029"])
def test_unicode_line_separators_cannot_hide_in_opaque_tcp_options(context, separator):
    # Catches bypassing the single-line contract through an unparsed raw field.
    with pytest.raises(PfSenseParseError):
        map_filterlog_line(changed(SYNTHETIC_TCP, **{"28": "before" + separator + "after"}), context)


@pytest.mark.parametrize("header", [
    "Sep 10 21:01:41 fixture-fw filterlog: ", "Sep  8 21:01:41 fixture-fw filterlog[123]: ",
])
def test_bsd_header_accepts_optional_pid_and_space_padded_day(context, header):
    fields, _, reason = map_filterlog_line(header + SYNTHETIC_PASS[len(HEADER):], context)
    assert reason is None
    assert fields["hostname"] == "fixture-fw"


@pytest.mark.parametrize("line", [
    SYNTHETIC_PASS[len(HEADER):], "prefix " + SYNTHETIC_PASS, SYNTHETIC_PASS + "\n",
    SYNTHETIC_PASS.replace("filterlog[1]", "filterlog[-1]"),
    SYNTHETIC_PASS.replace("filterlog[1]", "filterlog[" + "1" * 129 + "]"),
    SYNTHETIC_PASS.replace("filterlog[1]", "other"),
    SYNTHETIC_PASS.replace("Sep 10", "Feb 30"),
    "<134>1 2026-09-10T21:01:41+07:00 fixture-fw filterlog - - - test",
])
def test_unrecognized_or_malformed_headers_fail(context, line):
    with pytest.raises(PfSenseParseError):
        map_filterlog_line(line, context)


@pytest.mark.parametrize("line, reason", [
    ("", "blank_line"), ("   ", "blank_line"),
    ("Sep  8 23:01:00 fixture-fw newsyslog[1]: logfile turned over due to size>500K", "rotation_notice"),
    ("Sep  8 23:01:00 fixture-fw newsyslog: logfile turned over due to size>1M", "rotation_notice"),
    (changed(**{"8": "6"}), "unsupported_ip_version"),
    (HEADER + "4,,,1000000001,fixture0,match,block,in,6", "unsupported_ip_version"),
    (changed(**{"15": "2", "16": "igmp"}) + " ", "unsupported_protocol"),
])
def test_explicit_skips_do_not_invent_events_or_validate_protocol_payload(context, line, reason):
    fields, metadata, actual = map_filterlog_line(line, context)
    assert fields is None
    assert actual == reason
    assert "raw_payload" not in metadata


@pytest.mark.parametrize("line", [
    changed(**{"8": "6", "6": "reject"}), changed(**{"8": "6", "7": "sideways"}),
    changed(**{"8": "6", "0": "not-a-rule"}),
    "Sep  8 23:01:00 fixture-fw newsyslog[1]: unrelated message",
    "Sep  8 23:01:00 fixture-fw newsyslog[1]: logfile turned over due to size>0K",
    "Sep  8 23:01:00 fixture-fw newsyslog[1]: logfile turned over due to size>-1K",
    "Sep  8 23:01:00 fixture-fw newsyslog[1]: logfile turned over due to size>500K extra",
    "Feb 30 23:01:00 fixture-fw newsyslog[1]: logfile turned over due to size>500K",
])
def test_skip_classification_still_requires_valid_common_fields_and_notice(context, line):
    with pytest.raises(PfSenseParseError):
        map_filterlog_line(line, context)
