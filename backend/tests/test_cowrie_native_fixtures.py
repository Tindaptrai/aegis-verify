"""Audited real Cowrie derivatives; logged command text stays inert."""

from hashlib import sha256
import json
from pathlib import Path

from aegis_verify.connectors.cowrie import iter_cowrie_file, parse_cowrie_jsonl
from aegis_verify.models import CanonicalEventV2


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "tests/fixtures/cowrie/native"
CONTEXT = {
    "environment_id": "native-fixture-lab",
    "sensor_id": "cowrie-native-fixture-01",
    "ingested_at": "2026-09-11T04:39:42Z",
}
SOURCE_LINES = (8, 11, 12, 13, 15, 16, 17, 19)
SOURCE_LINE_HASHES = (
    "2247f723ac751a6b0d261b1d3cfdb537c9338592a4aa0782757d16f1fa8829bc",
    "5f27d3d1efb0ebf80a9b7359917eb367c5169fa028d06838d0cbce100b26d6e5",
    "d9e94b73007039c394424d2302abcc5cc713200e76366a750bde3931df21465f",
    "95f428e120d9429194a4e268044864fcc85915ab989226b82c578f248076fad5",
    "2bcef35f6676bb27e86298bdba801e6991e078cbbce656d04f5fe21437b528cc",
    "d4ddb739afa6391d81f3c1f0b1b3f0a679ba5958137611cfdc6f4ea1eee5934c",
    "b55ccca8b0e964f82c7b900ef3d988db9b649b06317828c1d0c1f8eff5c1bcf0",
    "3000c5fd76ba0959dcce3e2054f5df4136a0ce03c6dd342083ffdc6d790179fa",
)
EXPECTED = (
    ("cowrie.session.connect", "2026-04-16T15:16:04.729302Z", "observed", None),
    ("cowrie.login.failed", "2026-04-16T15:16:06.808463Z", "login", "failure"),
    ("cowrie.login.success", "2026-04-16T15:16:25.412634Z", "login", "success"),
    ("cowrie.client.size", None, None, None),
    ("cowrie.session.params", "2026-04-16T15:16:25.433094Z", "observed", None),
    ("cowrie.command.input", "2026-04-16T15:16:28.961927Z", "command", None),
    ("cowrie.command.input", "2026-04-16T15:16:30.882096Z", "command", None),
    ("cowrie.session.closed", "2026-04-16T15:16:30.886255Z", "observed", None),
)


def manifest():
    return json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))


def expected_digest(namespace, values):
    payload = json.dumps([namespace, *values], ensure_ascii=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


def test_real_sequence_is_available():
    fixture = FIXTURE_DIR / "session-sequence.sanitized.jsonl"
    assert fixture.is_file()


def test_manifest_preserves_audited_source_and_derivative_coordinates():
    document = manifest()
    assert document["manifest_version"] == "1.0"
    assert document["profile"] == "cowrie-jsonl-v1"
    assert document["review_status"] == "controller_audited_pending_human_review"
    assert document["parser_context"] == CONTEXT
    assert document["source_file"] == "cowrie.json.2026-04-16"
    assert document["source_sha256"] == (
        "3e26949ef450518ca66bb492bba34fda0f6991e9b9137f5da90049589464836e"
    )
    assert document["derivative_sha256"] == (
        "846948ff724363676952c060fa5d63f6da7d5561fefecd951d67d591bf8eb762"
    )
    assert [record["derivative_line"] for record in document["records"]] == list(
        range(1, 9)
    )
    assert tuple(record["source_line"] for record in document["records"]) == SOURCE_LINES
    assert tuple(
        record["source_line_sha256"] for record in document["records"]
    ) == SOURCE_LINE_HASHES
    assert tuple(record["event_type"] for record in document["records"]) == tuple(
        item[0] for item in EXPECTED
    )
    assert [record["expected_status"] for record in document["records"]] == [
        "parsed", "parsed", "parsed", "skipped", "parsed", "parsed", "parsed", "parsed"
    ]
    assert document["removed_fields"] == ["message", "password"]


def test_exact_physical_lines_drive_native_evidence_identity():
    document = manifest()
    path = FIXTURE_DIR / document["file"]
    raw = path.read_bytes()
    physical_lines = raw.splitlines(keepends=True)
    source_ref = document["source_ref"]

    assert sha256(raw).hexdigest() == document["derivative_sha256"]
    assert source_ref == "cowrie-native-" + document["derivative_sha256"]
    assert len(physical_lines) == 8
    assert all(line.endswith(b"\n") and b"\r" not in line for line in physical_lines)

    parsed = parse_cowrie_jsonl(raw, **(CONTEXT | {"source_ref": source_ref}))
    assert tuple(iter_cowrie_file(path, **(CONTEXT | {"source_ref": source_ref}))) == parsed
    for index, (line, record) in enumerate(zip(physical_lines, parsed, strict=True), start=1):
        line_hash = sha256(line).hexdigest()
        provenance = record.provenance
        evidence_digest = expected_digest(
            "cowrie-native-evidence-v1",
            (CONTEXT["environment_id"], CONTEXT["sensor_id"], source_ref, index, line_hash),
        )
        assert provenance.record_index == provenance.line_start == provenance.line_end == index
        assert provenance.raw_event_hash == line_hash
        assert provenance.raw_event_ref == f"{source_ref}#L{index}-L{index}"
        assert provenance.event_id == "cowrie:native-evidence-v1:" + evidence_digest
        if record.event is not None:
            assert record.event.raw_event_hash == line_hash
            assert record.event.raw_event_ref == provenance.raw_event_ref
            assert record.event.event_id == provenance.event_id


def test_real_same_session_sequence_maps_only_present_source_facts():
    document = manifest()
    path = FIXTURE_DIR / document["file"]
    raw_lines = path.read_bytes().splitlines(keepends=True)
    source_documents = [json.loads(line) for line in raw_lines]
    records = parse_cowrie_jsonl(
        b"".join(raw_lines), **(CONTEXT | {"source_ref": document["source_ref"]})
    )

    assert [source["eventid"] for source in source_documents] == [
        item[0] for item in EXPECTED
    ]
    parsed = [record for record in records if record.status == "parsed"]
    skipped = [record for record in records if record.status == "skipped"]
    assert len(parsed) == 7 and len(skipped) == 1
    assert {record.provenance.source_event_type for record in parsed} == {
        "cowrie.session.connect",
        "cowrie.login.failed",
        "cowrie.login.success",
        "cowrie.session.params",
        "cowrie.command.input",
        "cowrie.session.closed",
    }
    assert skipped[0].reason == "unsupported_event_type"
    assert skipped[0].provenance.record_index == 4
    assert skipped[0].provenance.source_event_type == "cowrie.client.size"
    assert skipped[0].event is None
    assert skipped[0].provenance.session is skipped[0].provenance.session_key is None

    session_digest = expected_digest(
        "cowrie-session-v1",
        (CONTEXT["environment_id"], CONTEXT["sensor_id"], "native-session-01"),
    )
    assert {record.provenance.session for record in parsed} == {"native-session-01"}
    assert {record.provenance.session_key for record in parsed} == {
        "cowrie:session-v1:" + session_digest
    }
    assert [record.provenance.source_event_type for record in parsed] == [
        "cowrie.session.connect",
        "cowrie.login.failed",
        "cowrie.login.success",
        "cowrie.session.params",
        "cowrie.command.input",
        "cowrie.command.input",
        "cowrie.session.closed",
    ]

    for record, source, (_, timestamp, action, outcome) in zip(
        records, source_documents, EXPECTED, strict=True
    ):
        if record.status == "skipped":
            continue
        event, provenance = record.event, record.provenance
        assert type(event) is CanonicalEventV2
        assert event.timestamp.isoformat() == timestamp
        assert event.ingested_at.isoformat() == "2026-09-11T04:39:42Z"
        assert event.source_type == event.event_provider == "cowrie"
        assert event.environment_id == "native-fixture-lab"
        assert event.event_action == action
        assert (str(event.src_ip) if event.src_ip is not None else None) == source.get("src_ip")
        assert (str(event.dst_ip) if event.dst_ip is not None else None) == source.get("dst_ip")
        assert event.src_port == source.get("src_port")
        assert event.dst_port == source.get("dst_port")
        assert event.protocol == source.get("protocol")
        assert event.username == (source.get("username") if action == "login" else None)
        assert event.command_line == (source.get("input") if action == "command" else None)
        assert event.source_record_id is None
        assert provenance.source_event_type == source["eventid"]
        assert provenance.source_sensor == source["sensor"]
        assert provenance.source_uuid == source["uuid"]
        assert provenance.arch == source.get("arch")
        assert provenance.authentication_outcome == outcome
        assert provenance.source_fraction_digits == 6
        assert provenance.mapping_version == "cowrie-native-v1"
        assert provenance.input_profile == "cowrie-jsonl-v1"
        assert provenance.payload_basis == "cowrie.native"
        assert provenance.timestamp_basis == "cowrie.timestamp"

    connect = records[0].event
    assert str(connect.src_ip) == str(connect.dst_ip) == "198.51.100.20"
    assert (connect.src_port, connect.dst_port) == (36572, 2222)
    for record in (records[1], records[2], records[4], records[5], records[6], records[7]):
        assert record.event.dst_ip is None
        assert record.event.src_port is None
        assert record.event.dst_port is None
    assert [records[5].event.command_line, records[6].event.command_line] == [
        "whoami", "exit"
    ]


def test_native_derivative_contains_only_reviewed_aliases_and_no_credentials():
    raw = (FIXTURE_DIR / "session-sequence.sanitized.jsonl").read_bytes()
    documents = [json.loads(line) for line in raw.splitlines()]

    assert b"password" not in raw.lower()
    assert b"message" not in raw.lower()
    assert {document["src_ip"] for document in documents} == {"198.51.100.20"}
    assert {document["session"] for document in documents} == {"native-session-01"}
    assert {document["sensor"] for document in documents} == {"native-sensor-01"}
    assert {document["uuid"] for document in documents} == {
        "00000000-0000-4000-8000-000000000001"
    }
    assert {document["username"] for document in documents if "username" in document} == {
        "native-user-01"
    }
    assert all("password" not in document and "message" not in document for document in documents)
