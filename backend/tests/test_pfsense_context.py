"""Explicit pfSense fixture context and immutable outcome boundary."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from aegis_verify.connectors.pfsense import (
    PfSenseContext,
    PfSenseParseError,
    PfSenseProvenance,
    PfSenseRecord,
    make_context,
    source_timestamp,
)
from aegis_verify.models import CanonicalEventV2, PreciseTimestamp


CONTEXT = dict(
    source_ref="unit-log",
    environment_id=" unit-env ",
    sensor_id="unit-fw",
    ingested_at="2026-09-10T15:00:00Z",
    source_year=2026,
    source_utc_offset="+07:00",
)


def make_provenance(**changes):
    values = dict(
        source_ref="unit-log",
        sensor_id="unit-fw",
        record_index=1,
        line_start=1,
        line_end=1,
        event_id="pfsense:unit-event",
        raw_event_hash="a" * 64,
        raw_event_ref="unit-log#L1-L1",
        timestamp_basis="bsd_syslog_with_caller_context",
        source_year=2026,
        source_utc_offset="+07:00",
        warnings=("year_and_offset_supplied_by_caller",),
    )
    return PfSenseProvenance(**(values | changes))


def make_event(**changes):
    values = dict(
        event_id="pfsense:unit-event",
        timestamp="2026-09-10T14:01:41Z",
        ingested_at="2026-09-10T15:00:00Z",
        source_type="pfsense",
        environment_id=" unit-env ",
        raw_event_hash="a" * 64,
        raw_event_ref="unit-log#L1-L1",
    )
    return CanonicalEventV2(**(values | changes))


def test_explicit_year_offset_preserves_second_precision():
    # Catches replacement of caller context with machine time or fractional padding.
    context = make_context(**CONTEXT)

    value = source_timestamp("Sep 10 21:01:41", context)

    assert value.isoformat() == "2026-09-10T14:01:41Z"
    assert value.fractional_digits == 0
    assert context.environment_id == " unit-env "
    assert context.source_year == 2026
    assert context.source_utc_offset == "+07:00"
    assert context.ingested_at.isoformat() == "2026-09-10T15:00:00Z"


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Jan  1 00:00:00", "2023-12-31T17:00:00Z"),
        ("Feb 29 23:59:59", "2024-02-29T16:59:59Z"),
        ("Dec 31 23:59:59", "2024-12-31T16:59:59Z"),
    ],
)
def test_source_timestamp_uses_english_calendar_without_locale(text, expected):
    # Catches locale-dependent month parsing and mishandling of space-padded days.
    context = make_context(**(CONTEXT | {"source_year": 2024}))
    assert source_timestamp(text, context).isoformat() == expected


@pytest.mark.parametrize(
    "field, value",
    [
        ("source_year", True),
        ("source_year", 0),
        ("source_year", 10000),
        ("source_utc_offset", "-00:00"),
        ("source_utc_offset", "+24:00"),
        ("source_utc_offset", "+07:60"),
        ("source_utc_offset", "+0700"),
        ("source_utc_offset", "+\u0660\u0667:00"),
        ("source_ref", "../SECRET"),
        ("source_ref", ""),
        ("sensor_id", "unit/fw"),
        ("sensor_id", "x" * 129),
        ("environment_id", " "),
        ("environment_id", chr(0xD800) + "SECRET"),
        ("environment_id", "\u00e9" * 65),
        ("ingested_at", datetime(2026, 9, 10, 15, 0, 0)),
    ],
)
def test_context_rejects_missing_or_untrusted_caller_values_safely(field, value):
    # Each case catches accepting a value that would make provenance ambiguous/unsafe.
    with pytest.raises(PfSenseParseError) as caught:
        make_context(**(CONTEXT | {field: value}))

    diagnostic = caught.value.diagnostic
    assert diagnostic.code == "invalid_context"
    assert diagnostic.field_path == field
    assert caught.value.code == diagnostic.code
    assert caught.value.field_path == diagnostic.field_path
    assert "SECRET" not in str(caught.value)
    assert caught.value.__suppress_context__


def test_context_is_frozen_extra_forbid_and_validates_direct_construction():
    context = make_context(**CONTEXT)
    with pytest.raises(ValidationError):
        PfSenseContext(**(CONTEXT | {"source_year": True}))
    with pytest.raises(ValidationError):
        PfSenseContext(**(CONTEXT | {"unexpected": "value"}))
    with pytest.raises(ValidationError):
        context.source_year = 2025


@pytest.mark.parametrize(
    "text",
    [
        "Feb 30 00:00:00",
        "Feb 29 00:00:00",
        "Sep 10 24:00:00",
        "Sep 10 23:60:00",
        "Sep 10 23:59:60",
        "sep 10 21:01:41",
        "Sep 10 21:01:41 SECRET",
        "S\u00e9p 10 21:01:41",
    ],
)
def test_invalid_source_timestamp_is_rejected_without_echo(text):
    # Catches calendar normalization and leaking a malformed raw header timestamp.
    context = make_context(**CONTEXT)
    with pytest.raises(PfSenseParseError) as caught:
        source_timestamp(text, context)
    assert caught.value.code == "invalid_timestamp"
    assert caught.value.field_path == "timestamp"
    assert "SECRET" not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize(
    "year, offset, text",
    [
        (1, "+23:59", "Jan  1 00:00:00"),
        (9999, "-23:59", "Dec 31 23:59:59"),
    ],
)
def test_source_timestamp_rejects_utc_range_overflow(year, offset, text):
    context = make_context(
        **(CONTEXT | {"source_year": year, "source_utc_offset": offset})
    )
    with pytest.raises(PfSenseParseError) as caught:
        source_timestamp(text, context)
    assert caught.value.code == "invalid_timestamp"


def test_parse_error_sanitizes_unknown_diagnostics_and_positions():
    # Catches attacker-controlled codes/paths entering logs through public errors.
    error = PfSenseParseError(
        "SECRET_CODE", "SECRET_FIELD", line=0, record_index=True
    )
    assert error.code == "invalid_field"
    assert error.field_path is None
    assert error.line is None
    assert error.record_index == 1
    assert "SECRET" not in str(error)


def test_parsed_record_requires_matching_evidence_identity():
    # Catches envelopes pairing an event with provenance for different evidence.
    event = make_event()
    record = PfSenseRecord(status="parsed", event=event, provenance=make_provenance())
    assert record.reason is None
    assert record.event is event

    mismatches = [
        make_provenance(event_id="pfsense:other"),
        make_provenance(raw_event_hash="b" * 64),
        make_provenance(raw_event_ref="unit-log#L2-L2"),
    ]
    for provenance in mismatches:
        with pytest.raises(ValidationError):
            PfSenseRecord(status="parsed", event=event, provenance=provenance)


@pytest.mark.parametrize(
    "values",
    [
        {"event": None},
        {"reason": "blank_line"},
        {"status": "parsed", "reason": "unsupported_protocol"},
    ],
)
def test_parsed_record_rejects_missing_event_or_skip_reason(values):
    # Catches partially populated parsed outcomes that consumers could misread.
    data = dict(status="parsed", reason=None, event=make_event()) | values
    with pytest.raises(ValidationError):
        PfSenseRecord(**data, provenance=make_provenance())


@pytest.mark.parametrize(
    "reason",
    [
        "blank_line",
        "rotation_notice",
        "unsupported_ip_version",
        "unsupported_protocol",
    ],
)
def test_skipped_record_has_no_event_identity(reason):
    # Catches skips masquerading as canonical security events.
    provenance = make_provenance(
        event_id=None,
        timestamp_basis=None,
        warnings=(),
    )
    record = PfSenseRecord(
        status="skipped", reason=reason, event=None, provenance=provenance
    )
    assert record.event is None
    assert record.provenance.event_id is None


@pytest.mark.parametrize(
    "changes",
    [
        {"event": make_event()},
        {"provenance": make_provenance()},
        {"reason": None},
        {"reason": "unknown"},
    ],
)
def test_skipped_record_rejects_event_identity_or_invalid_reason(changes):
    # Catches invalid skip combinations and non-contract reason strings.
    data = dict(
        status="skipped",
        reason="blank_line",
        event=None,
        provenance=make_provenance(event_id=None),
    )
    with pytest.raises(ValidationError):
        PfSenseRecord(**(data | changes))


def test_provenance_defaults_absent_source_metadata_to_null():
    # Catches invented vendor facts when optional filterlog cells are absent.
    provenance = make_provenance()
    values = provenance.model_dump()
    optional = (
        "interface",
        "direction",
        "reason",
        "rule_number",
        "subrule",
        "anchor",
        "tracker",
        "protocol_id",
        "protocol_text",
        "timestamp_text",
        "nat_context",
    )
    assert all(values[field] is None for field in optional)
    assert provenance.mapping_version == "pfsense-filterlog-v1"
    assert provenance.input_profile == "pfsense-filterlog-bsd-ipv4-tcp-udp-v1"
    with pytest.raises(ValidationError):
        PfSenseProvenance(**(provenance.model_dump() | {"unexpected": "value"}))


def test_records_and_provenance_are_immutable():
    provenance = make_provenance()
    record = PfSenseRecord(status="parsed", event=make_event(), provenance=provenance)
    with pytest.raises(ValidationError):
        provenance.event_id = "changed"
    with pytest.raises(ValidationError):
        record.status = "skipped"


def test_source_timestamp_requires_real_context_and_text():
    context = make_context(**CONTEXT)
    for text in (None, b"Sep 10 21:01:41", True):
        with pytest.raises(PfSenseParseError) as caught:
            source_timestamp(text, context)
        assert caught.value.code == "invalid_timestamp"
    with pytest.raises(PfSenseParseError) as caught:
        source_timestamp("Sep 10 21:01:41", object())
    assert caught.value.code == "invalid_context"
    assert caught.value.field_path is None


def test_context_accepts_precise_timestamp_and_aware_datetime():
    precise = PreciseTimestamp.parse("2026-09-10T15:00:00.123456789Z")
    from_precise = make_context(**(CONTEXT | {"ingested_at": precise}))
    from_datetime = make_context(
        **(
            CONTEXT
            | {
                "ingested_at": datetime.fromisoformat(
                    "2026-09-10T22:00:00.123456+07:00"
                )
            }
        )
    )
    assert from_precise.ingested_at is precise
    assert from_datetime.ingested_at.isoformat() == "2026-09-10T15:00:00.123456Z"
