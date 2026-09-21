"""The SCN-002 Suricata marker rule is reviewed content, not a lab artefact.

The template lives under version control so the signature can be reviewed and
reproduced. Lab addresses, the destination port and the SID stay placeholders,
because committing a rendered rule would put lab values into Git and would make
the reviewed content indistinguishable from one deployment of it.

These tests check the template's text. They do not run Suricata, so a passing
test says the content is the reviewed shape, never that Suricata accepts it or
that the signature fires on anything.
"""

import re
from pathlib import Path
from string import Template

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_PATH = ROOT / "detections" / "suricata" / "scn-002" / "marker.rules.template"
PLACEHOLDERS = {"src_net", "dst_ip", "dst_port", "sid"}
MARKER = "AEGIS-SCN002-TEST"


def _raw() -> bytes:
    return TEMPLATE_PATH.read_bytes()


def _text() -> str:
    return _raw().decode("utf-8")


def test_the_template_is_committed_as_lf_text_with_one_trailing_newline():
    raw = _raw()
    assert raw, "template must not be empty"
    assert b"\r" not in raw, "template must be LF only"
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")


def test_the_template_exposes_exactly_the_expected_placeholders():
    found = {match.group("named") or match.group("braced")
             for match in Template.pattern.finditer(_text())
             if match.group("named") or match.group("braced")}
    assert found == PLACEHOLDERS


def test_the_template_holds_exactly_one_rule():
    rules = [line for line in _text().splitlines() if line.strip().startswith("alert ")]
    assert len(rules) == 1


def test_the_rule_matches_the_reviewed_marker_within_a_bounded_depth():
    text = _text()
    assert f'content:"{MARKER}"' in text
    depth = re.search(r"depth:(\d+);", text)
    assert depth is not None, "an unbounded content match would scan whole packets"
    assert 0 < int(depth.group(1)) <= 128


def test_the_rule_declares_controlled_test_traffic_and_a_revision():
    text = _text()
    # This is approved test traffic, so it must not be classed as a real attack.
    assert "classtype:policy-violation;" in text
    assert re.search(r"\brev:\d+;", text) is not None
    assert "metadata:" in text
    assert 'msg:"' in text and "SCN-002" in text


def test_no_lab_value_can_be_committed_through_this_template():
    text = _text()
    assert re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text) is None, "no IPv4 literal"
    assert re.search(r"sid:\s*\d", text) is None, "the SID stays a placeholder"
    # The destination port is a lab choice and must not be frozen here either.
    assert re.search(r"->\s*\$dst_ip\s+\$dst_port\b", text) is not None


def test_rendering_produces_one_line_of_the_expected_shape():
    rendered = Template(_text()).substitute(
        src_net="$HOME_NET", dst_ip="203.0.113.10", dst_port="65000", sid="1000101"
    )
    line = " ".join(rendered.split())
    assert line.startswith("alert udp $HOME_NET any -> 203.0.113.10 65000 (")
    assert line.endswith(")")
    assert "sid:1000101;" in line
    assert MARKER in line
    # Shape only. Nothing here asks Suricata whether it would load this rule.
