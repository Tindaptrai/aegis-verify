"""SCN-003 detection content is reviewed text, not a lab artefact.

Two templates: a Suricata rule that alerts on one TCP SYN to the approved decoy
endpoint, and a Wazuh child rule that fires on one Cowrie login failure whose
username is the run marker. Deployment values (networks, decoy address and
port, the Wazuh parent group) stay template variables; the two IDs are fixed
in Git as reviewed literals (plan of 2026-09-24).

These tests read the files. They do not run Suricata or wazuh-logtest, so a
passing test says the content has the reviewed shape, never that either engine
loads it or that it fires on anything.
"""

import re
from pathlib import Path
from string import Template
from xml.etree import ElementTree

import pytest

ROOT = Path(__file__).resolve().parents[2]
SURICATA = ROOT / "detections" / "suricata" / "scn-003" / "decoy-connect.rules.template"
WAZUH = ROOT / "detections" / "wazuh" / "scn-003" / "login-failed.xml.template"
SURICATA_SID = "1000012"
WAZUH_RULE_ID = "120003"
SURICATA_VARIABLES = {"src_net", "decoy_ip", "decoy_port"}
WAZUH_VARIABLES = {"parent_group"}
USERNAME_GRAMMAR = r"\AAEGIS-SCN003-[0-9a-f]{8}\z"
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def variables(text: str) -> set[str]:
    return {m.group("named") or m.group("braced") for m in Template.pattern.finditer(text)
            if m.group("named") or m.group("braced")}


@pytest.mark.parametrize("path", [SURICATA, WAZUH], ids=["suricata", "wazuh"])
def test_templates_are_lf_text_with_one_trailing_newline(path):
    raw = path.read_bytes()
    assert raw and b"\r" not in raw
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")


@pytest.mark.parametrize("path", [SURICATA, WAZUH], ids=["suricata", "wazuh"])
def test_no_lab_value_or_credential_is_committed(path):
    text = path.read_text("utf-8")
    assert IPV4.search(text) is None
    assert re.search(r"password|passwd|secret|token", text, re.IGNORECASE) is None


def test_suricata_template_exposes_only_deployment_variables():
    assert variables(SURICATA.read_text("utf-8")) == SURICATA_VARIABLES


def test_suricata_rule_is_one_tcp_syn_alert_to_the_decoy_with_the_fixed_sid():
    text = SURICATA.read_text("utf-8")
    assert text.count("alert tcp ") == 1 and text.count("\n") == 1
    assert re.search(r"->\s*\$decoy_ip\s+\$decoy_port\b", text)
    assert "flow:to_server;" in text
    assert re.search(r"flags:S(?:,12)?;", text), "the rule observes the SYN only"
    assert f"sid:{SURICATA_SID};" in text and re.search(r"\brev:\d+;", text)
    assert 'msg:"AEGIS SCN-003 decoy connection"' in text
    assert "classtype:policy-violation;" in text and "metadata:" in text
    assert "content:" not in text, "a SYN carries no payload to match"


def test_suricata_rendering_keeps_the_shape():
    rendered = Template(SURICATA.read_text("utf-8")).substitute(
        src_net="$HOME_NET", decoy_ip="203.0.113.30", decoy_port="22")
    line = " ".join(rendered.split())
    assert line.startswith("alert tcp $HOME_NET any -> 203.0.113.30 22 (") and line.endswith(")")
    assert f"sid:{SURICATA_SID};" in line


def test_wazuh_template_exposes_only_the_parent_group_variable():
    assert variables(WAZUH.read_text("utf-8")) == WAZUH_VARIABLES


def test_wazuh_rule_is_one_cowrie_login_failure_marker_with_the_fixed_id():
    rendered = Template(WAZUH.read_text("utf-8")).substitute(parent_group="cowrie")
    root = ElementTree.fromstring(rendered)
    assert root.tag == "group" and "cowrie" in root.attrib["name"].split(",")
    rules = root.findall("rule")
    assert len(rules) == 1
    rule = rules[0]
    assert rule.attrib == {"id": WAZUH_RULE_ID, "level": "5"}
    assert rule.findtext("if_group") == "cowrie"
    fields = {node.attrib["name"]: (node.attrib.get("type"), node.text) for node in rule.findall("field")}
    # Wazuh rules name JSON-decoded fields without the `data.` prefix; the
    # SCN-001 templates proven with wazuh-logtest use `win.system.eventID`.
    assert fields == {"eventid": ("pcre2", r"\Acowrie\.login\.failed\z"),
                      "username": ("pcre2", USERNAME_GRAMMAR)}
    assert rule.findtext("options") == "no_email_alert"
    assert "not a compromise verdict" in (rule.findtext("description") or "")


@pytest.mark.parametrize("candidate, accepted", [
    ("AEGIS-SCN003-1a2b3c4d", True),
    ("AEGIS-SCN003-DEADBEEF", False),
    ("AEGIS-SCN003-1a2b3c4", False),
    ("AEGIS-SCN002-1a2b3c4d", False),
    ("root", False),
    ("xAEGIS-SCN003-1a2b3c4d", False),
])
def test_username_grammar_accepts_only_run_markers(candidate, accepted):
    pattern = re.compile(USERNAME_GRAMMAR.replace(r"\A", "^").replace(r"\z", "$"))
    assert bool(pattern.match(candidate)) is accepted


def test_the_two_ids_are_not_claimed_elsewhere_in_the_repository():
    hits = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in {".git", ".venv", "node_modules", "dist", "__pycache__"}
                                     for part in path.parts):
            continue
        if path.suffix not in {".py", ".json", ".xml", ".template", ".md", ".yaml", ".yml", ".rules"}:
            continue
        if path in (SURICATA, WAZUH, Path(__file__)) or "superpowers" in path.parts \
                or path.name == "SCN003_DETECTION_CONTENT.md":
            continue
        text = path.read_text("utf-8", errors="ignore")
        if SURICATA_SID in text or WAZUH_RULE_ID in text:
            hits.append(path.relative_to(ROOT).as_posix())
    assert hits == [], hits
