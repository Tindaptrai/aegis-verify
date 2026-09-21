"""Explicit offline bundle intake over the six reviewed fixture parsers."""

from hashlib import sha256
from pathlib import Path
import shutil

import pytest


FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
INGESTED_AT = "2026-09-11T00:00:00Z"


def _entry(tmp_path, fixture, parser, source_ref, context):
    source = FIXTURES / fixture
    target = tmp_path / source.name
    shutil.copyfile(source, target)
    raw = target.read_bytes()
    return {
        "path": target.name,
        "source_ref": source_ref,
        "parser": parser,
        "sha256": sha256(raw).hexdigest(),
        "context": {"ingested_at": INGESTED_AT} | context,
    }, raw


def _manifest(files=()):
    from aegis_verify.intake.contracts import parse_manifest

    return parse_manifest(
        {
            "bundle_schema_version": "0.1.0",
            "environment_id": "synthetic-env",
            "files": list(files),
        }
    )


def test_empty_bundle_does_not_fabricate_events(tmp_path):
    from aegis_verify.intake.contracts import parse_manifest
    from aegis_verify.intake.loader import load_bundle

    manifest = parse_manifest(
        {
            "bundle_schema_version": "0.1.0",
            "environment_id": "synthetic-env",
            "files": [],
        }
    )
    result = load_bundle(tmp_path, manifest)
    assert result.events == ()
    assert result.ledger == ()


@pytest.mark.parametrize(
    "fixture,parser,source_ref,context,source_type,event_count,ledger_count",
    [
        (
            "wazuh/win4688.sanitized.json",
            "wazuh-win4688-v2",
            "win-4688",
            {"collection_mode": "direct"},
            "wazuh",
            1,
            1,
        ),
        (
            "suricata/suricata-wazuh-alert-001.sanitized.json",
            "suricata-wazuh-alert-v1",
            "suricata-wrapper",
            {"deployment_mode": "ids"},
            "suricata",
            1,
            1,
        ),
        (
            "suricata/eve-wan.sanitized.jsonl",
            "suricata-eve-jsonl-v1",
            "suricata-eve",
            {"sensor_id": "sensor-1", "deployment_mode": "ids"},
            "suricata",
            1,
            1,
        ),
        (
            "pfsense/tcp-block.sanitized.log",
            "pfsense-filterlog-bsd-ipv4-tcp-udp-v1",
            "pfsense-log",
            {
                "sensor_id": "firewall-1",
                "source_year": 2026,
                "source_utc_offset": "+07:00",
            },
            "pfsense",
            1,
            1,
        ),
        (
            "cowrie/login-failed.sanitized.json",
            "cowrie-wazuh-v1",
            "cowrie-wrapper",
            {"sensor_id": "honeypot-1"},
            "cowrie",
            1,
            1,
        ),
        (
            "cowrie/native/session-sequence.sanitized.jsonl",
            "cowrie-jsonl-v1",
            "cowrie-native",
            {"sensor_id": "honeypot-1"},
            "cowrie",
            7,
            8,
        ),
    ],
)
def test_explicit_registry_dispatches_existing_fixture_parser(
    tmp_path,
    fixture,
    parser,
    source_ref,
    context,
    source_type,
    event_count,
    ledger_count,
):
    from aegis_verify.intake.loader import load_bundle

    entry, raw = _entry(tmp_path, fixture, parser, source_ref, context)
    result = load_bundle(tmp_path, _manifest([entry]))

    assert len(result.events) == event_count
    assert len(result.ledger) == ledger_count
    assert {event.source_type for event in result.events} == {source_type}
    assert {item.parser for item in result.ledger} == {parser}
    assert {item.source_type for item in result.ledger} == {source_type}
    assert result.inventory == (
        {
            "source_ref": source_ref,
            "path": Path(entry["path"]).as_posix(),
            "parser": parser,
            "sha256": sha256(raw).hexdigest(),
            "context_fingerprint": result.inventory[0]["context_fingerprint"],
            # No configured label in these bundles, so it stays null.
            "display_label": None,
        },
    )
    assert len(result.inventory[0]["context_fingerprint"]) == 64


def test_wazuh_ledger_preserves_record_ref_and_locates_whole_document(tmp_path):
    from aegis_verify.intake.loader import load_bundle

    entry, raw = _entry(
        tmp_path,
        "wazuh/win4688.sanitized.json",
        "wazuh-win4688-v2",
        "wazuh-doc",
        {"collection_mode": "forwarded"},
    )
    item = load_bundle(tmp_path, _manifest([entry])).ledger[0]
    physical_lines = raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n"))

    assert item.raw_event_ref == "wazuh-doc#record=1"
    assert (item.line_start, item.line_end) == (1, physical_lines)
    assert item.raw_event_hash == sha256(raw).hexdigest()


def test_native_skipped_provenance_id_is_not_promoted_to_event_id(tmp_path):
    from aegis_verify.intake.loader import load_bundle

    entry, _ = _entry(
        tmp_path,
        "cowrie/native/session-sequence.sanitized.jsonl",
        "cowrie-jsonl-v1",
        "cowrie-native",
        {"sensor_id": "honeypot-1"},
    )
    result = load_bundle(tmp_path, _manifest([entry]))
    skipped = [item for item in result.ledger if item.status == "skipped"]

    assert len(skipped) == 1
    assert skipped[0].reason == "unsupported_event_type"
    assert skipped[0].event_id is None
    assert skipped[0].raw_event_ref == "cowrie-native#L4-L4"
    assert skipped[0].line_start == skipped[0].line_end == 4
    assert {item.event_id for item in result.ledger if item.event_id} == {
        event.event_id for event in result.events
    }


@pytest.mark.parametrize(
    "change,field",
    [
        ({"unexpected": True}, None),
        ({"bundle_schema_version": "0.2.0"}, "bundle_schema_version"),
        ({"environment_id": " "}, "environment_id"),
    ],
)
def test_manifest_is_closed_and_versioned(change, field):
    from aegis_verify.intake import IntakeError
    from aegis_verify.intake.contracts import parse_manifest

    data = {
        "bundle_schema_version": "0.1.0",
        "environment_id": "synthetic-env",
        "files": [],
    } | change
    with pytest.raises(IntakeError) as caught:
        parse_manifest(data)
    assert caught.value.code == "invalid_manifest"
    assert caught.value.field == field


def test_manifest_file_count_accepts_boundary_and_rejects_one_over():
    from aegis_verify.intake import IntakeError

    entries = [
        {
            "path": f"evidence-{index}.json",
            "source_ref": f"source-{index}",
            "parser": "wazuh-win4688-v2",
            "sha256": "0" * 64,
            "context": {
                "ingested_at": INGESTED_AT,
                "collection_mode": "unknown",
            },
        }
        for index in range(101)
    ]
    manifest = _manifest(entries[:100])
    assert len(manifest.files) == 100
    with pytest.raises(IntakeError) as caught:
        _manifest(entries)
    assert caught.value.code == "resource_limit"
    assert caught.value.field == "files"


def test_manifest_and_parser_context_are_frozen():
    from pydantic import ValidationError

    entry = {
        "path": "evidence.json",
        "source_ref": "source-1",
        "parser": "wazuh-win4688-v2",
        "sha256": "0" * 64,
        "context": {
            "ingested_at": INGESTED_AT,
            "collection_mode": "unknown",
        },
    }
    manifest = _manifest([entry])
    with pytest.raises(ValidationError):
        manifest.environment_id = "changed"
    with pytest.raises(ValidationError):
        manifest.files[0].context.collection_mode = "direct"


def test_parser_context_is_exact_and_matches_parser_key(tmp_path):
    from aegis_verify.intake import IntakeError

    entry, _ = _entry(
        tmp_path,
        "wazuh/win4688.sanitized.json",
        "wazuh-win4688-v2",
        "wazuh-doc",
        {"collection_mode": "direct"},
    )
    for context in (
        {"ingested_at": INGESTED_AT},
        entry["context"] | {"sensor_id": "not-a-wazuh-field"},
    ):
        with pytest.raises(IntakeError) as caught:
            _manifest([entry | {"context": context}])
        assert caught.value.code == "invalid_manifest"
        assert caught.value.file_index == 0
        assert caught.value.field == "context"


def test_pfsense_context_accepts_real_offset_domain_but_rejects_unknown_negative_zero(tmp_path):
    from aegis_verify.intake import IntakeError

    entry, _ = _entry(
        tmp_path,
        "pfsense/tcp-block.sanitized.log",
        "pfsense-filterlog-bsd-ipv4-tcp-udp-v1",
        "pfsense-offset",
        {
            "sensor_id": "firewall-1",
            "source_year": 2026,
            "source_utc_offset": "-00:30",
        },
    )
    assert _manifest([entry]).files[0].context.source_utc_offset == "-00:30"

    bad = entry | {
        "context": entry["context"] | {"source_utc_offset": "-00:00"}
    }
    with pytest.raises(IntakeError) as caught:
        _manifest([bad])
    assert caught.value.code == "invalid_manifest"
    assert caught.value.field == "context"


@pytest.mark.parametrize("parser", ["auto", [], {}, ["SECRET-PARSER"], {"SECRET-PARSER": "value"}])
def test_unknown_parser_is_rejected_without_fallback(tmp_path, parser):
    from aegis_verify.intake import IntakeError

    entry, _ = _entry(
        tmp_path,
        "wazuh/win4688.sanitized.json",
        "wazuh-win4688-v2",
        "wazuh-doc",
        {"collection_mode": "direct"},
    )
    with pytest.raises(IntakeError) as caught:
        _manifest([entry | {"parser": parser}])
    assert caught.value.code == "unknown_parser"
    assert caught.value.file_index == 0
    assert caught.value.field == "parser"
    assert "SECRET-PARSER" not in str(caught.value)


def test_source_refs_are_unique_before_any_evidence_is_opened(tmp_path):
    from aegis_verify.intake import IntakeError

    first, _ = _entry(
        tmp_path,
        "wazuh/win4688.sanitized.json",
        "wazuh-win4688-v2",
        "same-ref",
        {"collection_mode": "direct"},
    )
    second = first | {"path": "missing.json"}
    with pytest.raises(IntakeError) as caught:
        _manifest([first, second])
    assert caught.value.code == "duplicate_source_ref"
    assert caught.value.stage == "inputs"


def test_inventory_rejects_two_paths_to_same_physical_file(tmp_path):
    from aegis_verify.intake import IntakeError
    from aegis_verify.intake.loader import load_bundle

    first, _ = _entry(
        tmp_path,
        "wazuh/win4688.sanitized.json",
        "wazuh-win4688-v2",
        "first-ref",
        {"collection_mode": "direct"},
    )
    alias = tmp_path / "hardlink.json"
    alias.hardlink_to(tmp_path / first["path"])
    second = first | {"path": alias.name, "source_ref": "second-ref"}

    with pytest.raises(IntakeError) as caught:
        load_bundle(tmp_path, _manifest([first, second]))
    assert caught.value.code == "duplicate_file"
    assert caught.value.file_index == 1
    assert caught.value.field == "path"


def test_hash_uses_exact_bytes_and_mismatch_stops_before_parsing(tmp_path):
    from aegis_verify.intake import IntakeError
    from aegis_verify.intake.loader import load_bundle

    raw = b"\xef\xbb\xbf" + (FIXTURES / "wazuh/win4688.sanitized.json").read_bytes()
    path = tmp_path / "bom.json"
    path.write_bytes(raw)
    entry = {
        "path": path.name,
        "source_ref": "bom-doc",
        "parser": "wazuh-win4688-v2",
        "sha256": sha256(raw).hexdigest(),
        "context": {"ingested_at": INGESTED_AT, "collection_mode": "direct"},
    }
    result = load_bundle(tmp_path, _manifest([entry]))
    assert result.events[0].raw_event_hash == sha256(raw).hexdigest()

    with pytest.raises(IntakeError) as caught:
        load_bundle(tmp_path, _manifest([entry | {"sha256": "0" * 64}]))
    assert caught.value.code == "hash_mismatch"
    assert caught.value.file_index == 0


def test_late_malformed_line_aborts_whole_bundle_with_physical_coordinate(tmp_path):
    from aegis_verify.intake import IntakeError
    from aegis_verify.intake.loader import load_bundle

    first, _ = _entry(
        tmp_path,
        "wazuh/win4688.sanitized.json",
        "wazuh-win4688-v2",
        "first-good",
        {"collection_mode": "direct"},
    )
    raw = (
        b'{"eventid":"cowrie.client.size","width":80}\n'
        b'{"eventid":"PRIVATE-MALFORMED"\n'
    )
    path = tmp_path / "late.jsonl"
    path.write_bytes(raw)
    second = {
        "path": path.name,
        "source_ref": "late-bad",
        "parser": "cowrie-jsonl-v1",
        "sha256": sha256(raw).hexdigest(),
        "context": {"ingested_at": INGESTED_AT, "sensor_id": "honeypot-1"},
    }

    with pytest.raises(IntakeError) as caught:
        load_bundle(tmp_path, _manifest([first, second]))
    assert caught.value.code == "parser_error"
    assert caught.value.file_index == 1
    assert caught.value.line == 2
    assert "PRIVATE-MALFORMED" not in str(caught.value)


def test_parser_warnings_and_skip_coordinates_are_retained(tmp_path):
    from aegis_verify.intake.loader import load_bundle

    parsed, _ = _entry(
        tmp_path,
        "pfsense/tcp-block.sanitized.log",
        "pfsense-filterlog-bsd-ipv4-tcp-udp-v1",
        "parsed-firewall",
        {
            "sensor_id": "firewall-1",
            "source_year": 2026,
            "source_utc_offset": "+07:00",
        },
    )
    skipped, _ = _entry(
        tmp_path,
        "pfsense/ipv6-options.sanitized.log",
        "pfsense-filterlog-bsd-ipv4-tcp-udp-v1",
        "skipped-firewall",
        {
            "sensor_id": "firewall-1",
            "source_year": 2026,
            "source_utc_offset": "+07:00",
        },
    )
    result = load_bundle(tmp_path, _manifest([parsed, skipped]))

    assert result.ledger[0].warnings == ("year_and_offset_supplied_by_caller",)
    assert result.ledger[1].status == "skipped"
    assert result.ledger[1].reason == "unsupported_ip_version"
    assert (result.ledger[1].line_start, result.ledger[1].line_end) == (1, 1)
    assert result.ledger[1].raw_event_ref == "skipped-firewall#L1-L1"


@pytest.mark.parametrize(
    "limit_name,limit_value,want_code",
    [
        ("MAX_FILE_BYTES", 1, "input_too_large"),
        ("MAX_TOTAL_EVIDENCE_BYTES", 1, "resource_limit"),
        ("MAX_PHYSICAL_LINES", 0, "resource_limit"),
        ("MAX_EVENTS", 0, "resource_limit"),
    ],
)
def test_intake_resource_boundaries_stop_before_partial_result(
    tmp_path, monkeypatch, limit_name, limit_value, want_code
):
    import aegis_verify.intake.loader as loader
    from aegis_verify.intake import IntakeError

    entry, _ = _entry(
        tmp_path,
        "wazuh/win4688.sanitized.json",
        "wazuh-win4688-v2",
        "bounded-doc",
        {"collection_mode": "direct"},
    )
    monkeypatch.setattr(loader, limit_name, limit_value)
    with pytest.raises(IntakeError) as caught:
        loader.load_bundle(tmp_path, _manifest([entry]))
    assert caught.value.code == want_code
    assert caught.value.file_index == 0


@pytest.mark.parametrize(
    "limit_name,measurement,want_code",
    [
        ("MAX_FILE_BYTES", "bytes", "input_too_large"),
        ("MAX_TOTAL_EVIDENCE_BYTES", "bytes", "resource_limit"),
        ("MAX_PHYSICAL_LINES", "lines", "resource_limit"),
        ("MAX_EVENTS", "events", "resource_limit"),
    ],
)
def test_intake_resource_limits_accept_exact_boundary_and_reject_one_over(
    tmp_path, monkeypatch, limit_name, measurement, want_code
):
    """Catch inclusive-limit regressions such as changing ``>`` to ``>=``."""
    import aegis_verify.intake.loader as loader
    from aegis_verify.intake import IntakeError

    entry, raw = _entry(
        tmp_path,
        "wazuh/win4688.sanitized.json",
        "wazuh-win4688-v2",
        "exact-boundary-doc",
        {"collection_mode": "direct"},
    )
    actual = {
        "bytes": len(raw),
        "lines": raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n")),
        "events": 1,
    }[measurement]

    monkeypatch.setattr(loader, limit_name, actual)
    result = loader.load_bundle(tmp_path, _manifest([entry]))
    assert len(result.events) == 1

    monkeypatch.setattr(loader, limit_name, actual - 1)
    with pytest.raises(IntakeError) as caught:
        loader.load_bundle(tmp_path, _manifest([entry]))
    assert caught.value.code == want_code
    assert caught.value.file_index == 0


def _profile_and_context(*, declaration_id="detect", capability="supported", status="complete_for_scope"):
    from aegis_verify.validation import (
        AssertionRule,
        Binding,
        CollectionDeclaration,
        Correlation,
        EvaluationContext,
        EvaluationProfile,
        JoinPair,
        Predicate,
    )

    telemetry = AssertionRule(
        assertion_id="activity",
        role="telemetry",
        capability="supported",
        source_type="cowrie",
        scope=(Predicate(field="src_ip", op="eq", binding="target"),),
    )
    if capability == "supported":
        detection = AssertionRule(
            assertion_id="detect",
            role="detection",
            capability="supported",
            source_type="cowrie",
            scope=(Predicate(field="src_ip", op="eq", binding="target"),),
            match=(Predicate(field="rule_id", op="eq", value="55001"),),
            correlation=Correlation(
                anchor_assertion_id="activity",
                join_pairs=(JoinPair(target_field="src_ip", anchor_field="src_ip"),),
                min_delta_ns=0,
                max_delta_ns=1,
            ),
        )
    else:
        detection = AssertionRule(
            assertion_id="detect",
            role="detection",
            capability="unsupported",
            reason_code="synthetic-unsupported",
        )
    profile = EvaluationProfile(
        profile_id="synthetic-profile",
        profile_version="0.1.0",
        scenario_id="SCN-999",
        scenario_version="0.1.0",
        scenario_fingerprint="a" * 64,
        rules=(telemetry, detection),
    )
    declaration = CollectionDeclaration(
        assertion_id=declaration_id,
        status=status,
        **(
            {
                "confirmed_by": "synthetic-reviewer",
                "reference": "synthetic-reference",
                "coverage_start": "2026-01-01T00:00:00Z",
                "coverage_end": "2026-01-01T00:01:00Z",
                "no_sampling_or_truncation": True,
                "no_parse_errors_or_gaps": True,
                "clocks_adequate": True,
                "profile_fingerprint": "b" * 64,
                "scope_fingerprint": "c" * 64,
                "event_set_fingerprint": "d" * 64,
            }
            if status == "complete_for_scope"
            else {}
        ),
    )
    context = EvaluationContext(
        run_id="synthetic-run",
        environment_id="synthetic-env",
        start="2026-01-01T00:00:00Z",
        end="2026-01-01T00:01:00Z",
        bindings=(Binding(name="target", value="192.0.2.1"),),
        declarations=(declaration,),
    )
    return profile, context


def test_complete_detection_collection_conflicts_with_same_source_unsupported_skip(tmp_path):
    from aegis_verify.intake import IntakeError
    from aegis_verify.intake.loader import check_collection, load_bundle

    entry, _ = _entry(
        tmp_path,
        "cowrie/native/session-sequence.sanitized.jsonl",
        "cowrie-jsonl-v1",
        "cowrie-native",
        {"sensor_id": "honeypot-1"},
    )
    intake = load_bundle(tmp_path, _manifest([entry]))
    profile, context = _profile_and_context()

    with pytest.raises(IntakeError) as caught:
        check_collection(intake, profile, context)
    assert caught.value.code == "collection_conflict"
    assert caught.value.stage == "collection"


def test_unknown_collection_does_not_claim_completeness_over_unsupported_skip(tmp_path):
    from aegis_verify.intake.loader import check_collection, load_bundle

    entry, _ = _entry(
        tmp_path,
        "cowrie/native/session-sequence.sanitized.jsonl",
        "cowrie-jsonl-v1",
        "cowrie-native",
        {"sensor_id": "honeypot-1"},
    )
    intake = load_bundle(tmp_path, _manifest([entry]))
    profile, context = _profile_and_context(status="unknown")
    assert check_collection(intake, profile, context) is None


@pytest.mark.parametrize(
    "declaration_id,capability",
    [("stale", "supported"), ("detect", "unsupported")],
)
def test_collection_declaration_must_bind_supported_detection(
    declaration_id, capability
):
    from aegis_verify.intake import IntakeError, IntakeResult
    from aegis_verify.intake.loader import check_collection

    profile, context = _profile_and_context(
        declaration_id=declaration_id, capability=capability
    )
    with pytest.raises(IntakeError) as caught:
        check_collection(IntakeResult((), (), ()), profile, context)
    assert caught.value.code == "invalid_collection_declaration"
    assert caught.value.stage == "collection"
