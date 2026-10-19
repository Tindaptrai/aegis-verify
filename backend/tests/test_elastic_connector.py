"""Invented search hits only. These tests are not evidence of a live Lab B run."""

import copy
import hashlib
import importlib
import json
import traceback
import xml.etree.ElementTree as ET

import pytest


CONTEXT = dict(source_ref="synthetic-elastic", environment_id="synthetic-env",
               ingested_at="2026-01-01T00:02:00Z")
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
IMAGE = r"C:\Synthetic\powershell.exe"
PARENT = r"C:\Synthetic\runner.exe"
GUID = "{00000000-0000-0000-0000-000000000001}"


def connector():
    try:
        module = importlib.import_module("aegis_verify.connectors.elastic")
    except ModuleNotFoundError:
        module = None
    assert module is not None, "missing bounded Elastic connector"
    return module


def native_xml(code="1"):
    provider = "Microsoft-Windows-PowerShell" if code == "4104" else "Microsoft-Windows-Sysmon"
    data = {
        "1": {"UtcTime": "2026-01-01 00:00:00.123", "ProcessId": "4242",
              "Image": IMAGE, "ProcessGuid": GUID, "ParentProcessId": "4000",
              "ParentImage": PARENT, "ParentProcessGuid": "{00000000-0000-0000-0000-000000000002}",
              "User": r"SYNTHETIC\operator", "CommandLine": "powershell.exe -File synthetic.ps1"},
        "3": {"UtcTime": "2026-01-01 00:00:00.123", "ProcessId": "4242",
              "Image": IMAGE, "ProcessGuid": GUID, "User": r"SYNTHETIC\operator",
              "Protocol": "tcp", "SourceIp": "192.0.2.10", "SourcePort": "49152",
              "DestinationIp": "198.51.100.20", "DestinationPort": "8080"},
        "4104": {"MessageNumber": "1", "MessageTotal": "1",
                 "ScriptBlockText": "Write-Output 'SYNTHETIC_SAFE_MARKER'",
                 "ScriptBlockId": "synthetic-block", "Path": r"C:\Synthetic\synthetic.ps1"},
    }[code]
    root = ET.Element("Event", xmlns=NS)
    system = ET.SubElement(root, "System")
    ET.SubElement(system, "Provider", Name=provider)
    ET.SubElement(system, "EventID").text = code
    ET.SubElement(system, "TimeCreated", SystemTime="2026-01-01T00:00:00.1234567Z")
    ET.SubElement(system, "EventRecordID").text = "101"
    ET.SubElement(system, "Channel").text = provider + "/Operational"
    ET.SubElement(system, "Computer").text = "synthetic-endpoint"
    ET.SubElement(system, "Execution", ProcessID="4242")
    event_data = ET.SubElement(root, "EventData")
    for name, value in data.items():
        ET.SubElement(event_data, "Data", Name=name).text = value
    return ET.tostring(root, encoding="unicode")


def document(code="1"):
    provider = "Microsoft-Windows-PowerShell" if code == "4104" else "Microsoft-Windows-Sysmon"
    source = {
        "@timestamp": "2026-01-01T00:00:00.123Z",
        "event": {"kind": "event", "code": code, "provider": provider,
                  "original": native_xml(code), "ingested": "2026-01-01T00:00:03Z"},
        "winlog": {"event_id": code, "record_id": "101", "provider_name": provider,
                   "channel": provider + "/Operational", "computer_name": "synthetic-endpoint",
                   "process": {"pid": 4242}},
        "host": {"id": "synthetic-host-id", "hostname": "synthetic-endpoint", "name": "synthetic-endpoint"},
        "agent": {"id": "synthetic-collector", "name": "synthetic-endpoint", "type": "winlogbeat"},
        "fields": {"environment_id": "synthetic-env"},
    }
    if code in {"1", "3"}:
        source["process"] = {"pid": 4242, "executable": IMAGE, "entity_id": GUID}
    if code == "1":
        source["process"].update(command_line="powershell.exe -File synthetic.ps1",
                                  parent={"pid": 4000, "executable": PARENT})
    if code == "3":
        source.update(source={"ip": "192.0.2.10", "port": 49152},
                      destination={"ip": "198.51.100.20", "port": 8080},
                      network={"transport": "tcp"})
    if code == "4104":
        source["powershell"] = {"sequence": 1, "total": 1,
                                "file": {"script_block_id": "synthetic-block",
                                         "script_block_text": "Write-Output 'SYNTHETIC_SAFE_MARKER'"}}
    return {"_index": "synthetic-index", "_id": "synthetic-document-101", "_source": source}


def alert_document():
    result = document("4104")
    result["_index"] = "synthetic-alert-index"
    result["_id"] = "synthetic-alert-1"
    source = result["_source"]
    source["event"].pop("kind")
    source.update({"event.kind": "signal", "@timestamp": "2026-01-01T00:00:49.700Z",
                   "kibana.alert.start": "2026-01-01T00:00:49.9001234Z",
                   "kibana.alert.original_time": "2026-01-01T00:00:00.123Z",
                   "kibana.alert.rule.rule_id": "synthetic-safe-rule-v1",
                   "kibana.alert.rule.parameters": {"rule_id": "synthetic-safe-rule-v1"},
                   "kibana.alert.original_event.kind": "event",
                   "kibana.alert.rule.revision": 2,
                   "kibana.alert.uuid": "synthetic-alert-uuid",
                   "kibana.alert.severity": "low", "kibana.alert.risk_score": 21,
                   "kibana.alert.ancestors": [{"id": "synthetic-document-101", "index": "synthetic-index",
                                               "type": "event", "depth": 0}]})
    return result


def raw(document):
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def sample(kind):
    """Shared invented bytes for intake/CLI tests; no private lab values."""
    if kind == "security_alert":
        return raw(alert_document())
    return raw(document({"sysmon1": "1", "sysmon3": "3", "powershell4104": "4104"}[kind]))


def parse(value, code="1", **context):
    module = connector()
    name = {"1": "sysmon1", "3": "sysmon3", "4104": "powershell4104", "alert": "security_alert"}[code]
    api = getattr(module, "parse_elastic_" + name + "_document", None)
    assert callable(api), "missing explicit Elastic parser"
    return api(value, **(CONTEXT | context))


def mutate_xml(document, function):
    element = ET.fromstring(document["_source"]["event"]["original"])
    function(element)
    document["_source"]["event"]["original"] = ET.tostring(element, encoding="unicode")
    return document


def data_element(root, name):
    return root.find("{%s}EventData/{%s}Data[@Name='%s']" % (NS, NS, name))


@pytest.mark.parametrize("code", ["1", "3", "4104"])
def test_native_system_time_precision_and_export_provenance(code):
    encoded = raw(document(code)) + b"\r\n"
    result = parse(encoded, code)
    event, provenance = result.event, result.provenance
    assert event.timestamp.isoformat() == "2026-01-01T00:00:00.1234567Z"
    assert event.ingested_at.isoformat() == "2026-01-01T00:02:00Z"
    assert event.source_type == "elastic"
    assert event.source_record_id == "synthetic-document-101"
    assert event.asset_id == "synthetic-host-id"
    assert event.hostname == "synthetic-endpoint"
    assert event.process_id == 4242
    assert event.rule_id is None
    assert provenance.timestamp_basis == "windows.systemTime"
    assert provenance.source_fraction_digits == 7
    assert provenance.windows_event_id == code
    assert provenance.windows_record_id == "101"
    assert provenance.source_index == "synthetic-index"
    assert provenance.source_document_id == "synthetic-document-101"
    assert provenance.collector_agent_id == "synthetic-collector"
    assert provenance.normalized_timestamp == "2026-01-01T00:00:00.123Z"
    assert provenance.source_ingested_at == "2026-01-01T00:00:03Z"
    assert provenance.record_index == provenance.line_start == 1
    assert provenance.line_end == 1
    assert provenance.raw_event_ref == event.raw_event_ref == "synthetic-elastic#record=1"
    assert provenance.raw_event_hash == event.raw_event_hash == hashlib.sha256(encoded).hexdigest()
    identity = json.dumps(["elastic-evidence-v1", "synthetic-env", "synthetic-elastic", 1,
                           hashlib.sha256(encoded).hexdigest()], separators=(",", ":")).encode()
    assert event.event_id == "elastic:evidence-v1:" + hashlib.sha256(identity).hexdigest()
    assert provenance.event_id == event.event_id
    assert parse(encoded, code) == result


def test_process_creation_uses_native_full_image_and_command_facts():
    result = parse(raw(document()))
    assert result.event.process_name == IMAGE
    assert result.event.parent_process_name == PARENT
    assert result.event.command_line == "powershell.exe -File synthetic.ps1"
    assert result.event.username == r"SYNTHETIC\operator"
    assert result.provenance.process_guid == GUID
    assert result.provenance.parent_process_id == 4000
    assert result.provenance.sysmon_utc_time == "2026-01-01 00:00:00.123"


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_network_native_tuple_is_observation_not_prevention(protocol):
    value = document("3")
    value["_source"]["network"]["transport"] = protocol
    mutate_xml(value, lambda root: setattr(data_element(root, "Protocol"), "text", protocol))
    event = parse(raw(value), "3").event
    assert (str(event.src_ip), event.src_port, str(event.dst_ip), event.dst_port, event.protocol) == (
        "192.0.2.10", 49152, "198.51.100.20", 8080, protocol)
    assert event.event_action == "observed"
    assert event.command_line is None
    assert event.rule_id is None


def test_ipv6_address_aliases_compare_addresses_without_guessing_text():
    value = document("3")
    value["_source"]["source"]["ip"] = "2001:0db8:0:0:0:0:0:10"
    value["_source"]["destination"]["ip"] = "2001:db8::20"
    mutate_xml(value, lambda root: setattr(data_element(root, "SourceIp"), "text", "2001:db8::10"))
    mutate_xml(value, lambda root: setattr(data_element(root, "DestinationIp"), "text", "2001:0db8:0:0:0:0:0:20"))
    event = parse(raw(value), "3").event
    assert str(event.src_ip) == "2001:db8::10"
    assert str(event.dst_ip) == "2001:db8::20"


def test_powershell_script_text_is_not_a_command_line():
    result = parse(raw(document("4104")), "4104")
    assert result.event.file_path == r"C:\Synthetic\synthetic.ps1"
    assert result.event.command_line is None
    assert result.event.process_name is None
    assert result.provenance.script_block_id == "synthetic-block"
    assert result.provenance.message_number == result.provenance.message_total == 1


def test_documented_powershell_trim_is_explicit_and_preserves_raw_evidence():
    value = document("4104")
    mutate_xml(value, lambda root: setattr(data_element(root, "ScriptBlockText"), "text", "\tWrite-Output 'SYNTHETIC_SAFE_MARKER' \n"))
    encoded = raw(value)
    result = parse(encoded, "4104")
    assert result.event.raw_event_hash == hashlib.sha256(encoded).hexdigest()
    assert result.event.command_line is None
    assert result.provenance.warnings == ("powershell_script_text_xml_newlines_ascii_trim",)


@pytest.mark.parametrize("text", ["Write-Output 'CHANGED'", "\u00a0Write-Output 'SYNTHETIC_SAFE_MARKER'"])
def test_script_text_trim_does_not_hide_content_or_unreviewed_unicode_changes(text):
    value = document("4104")
    value["_source"]["powershell"]["file"]["script_block_text"] = text
    with pytest.raises(connector().ElasticParseError):
        parse(raw(value), "4104")


def test_alert_uses_own_start_clock_rule_and_immutable_lineage():
    result = parse(raw(alert_document()), "alert")
    event, provenance = result.event, result.provenance
    assert event.timestamp.isoformat() == "2026-01-01T00:00:49.9001234Z"
    assert event.event_provider == "elastic-security"
    assert event.rule_id == "synthetic-safe-rule-v1"
    assert event.process_id == 4242
    assert event.severity is None
    assert provenance.timestamp_basis == "kibana.alert.start"
    assert provenance.windows_system_time == "2026-01-01T00:00:00.1234567Z"
    assert provenance.rule_revision == 2
    assert provenance.alert_uuid == "synthetic-alert-uuid"
    assert provenance.alert_severity == "low"
    assert provenance.risk_score == 21
    assert provenance.ancestors[0].source_index == "synthetic-index"
    assert provenance.ancestors[0].source_document_id == "synthetic-document-101"
    assert provenance.ancestors[0].depth == 0
    for obj, name in [(result, "event"), (event, "rule_id"), (provenance, "rule_revision"),
                      (provenance.ancestors[0], "depth")]:
        with pytest.raises((ValueError, AttributeError, TypeError)):
            setattr(obj, name, None)


@pytest.mark.parametrize("code", ["1", "3", "4104"])
def test_no_copied_alert_can_satisfy_telemetry(code):
    value = document(code)
    value["_source"]["kibana.alert.rule.rule_id"] = "copied-rule"
    with pytest.raises(connector().ElasticParseError):
        parse(raw(value), code)
    with pytest.raises(connector().ElasticParseError):
        parse(raw(alert_document()), code)


def test_telemetry_never_infers_rule_id_from_ecs():
    value = document()
    value["_source"]["rule"] = {"id": "irrelevant-copy"}
    assert parse(raw(value)).event.rule_id is None


def test_optional_absent_fields_stay_null_and_unknown_fields_stay_raw():
    value = document()
    for name in ("host", "agent", "process"):
        value["_source"].pop(name)
    for key in ("Image", "ProcessId", "ParentImage", "ParentProcessId", "ProcessGuid", "ParentProcessGuid", "User", "CommandLine"):
        mutate_xml(value, lambda root, key=key: root.find("{%s}EventData" % NS).remove(data_element(root, key)))
    value["_source"]["unknown_private_vendor_field"] = "preserved-only-in-raw"
    event = parse(raw(value)).event
    for name in ("asset_id", "process_name", "process_id", "parent_process_name", "username", "command_line", "rule_id", "severity"):
        assert getattr(event, name) is None
    assert "preserved-only-in-raw" not in event.model_dump_json()


def test_missing_optional_native_facts_never_fall_back_to_export_aliases():
    value = document()
    def omit(root):
        system = root.find("{%s}System" % NS)
        system.remove(system.find("{%s}Computer" % NS))
        for name in ("Image", "ProcessId", "ProcessGuid", "CommandLine"):
            root.find("{%s}EventData" % NS).remove(data_element(root, name))
    mutate_xml(value, omit)
    event = parse(raw(value)).event
    assert event.hostname is None
    assert event.process_name is None
    assert event.process_id is None
    assert event.command_line is None


def test_windows_hostname_case_alias_preserves_native_spelling():
    value = document()
    value["_source"]["host"]["name"] = "SYNTHETIC-ENDPOINT"
    assert parse(raw(value)).event.hostname == "synthetic-endpoint"


@pytest.mark.parametrize("name", ["TimeCreated", "EventRecordID", "EventID", "Provider", "Channel"])
def test_missing_required_native_identity_or_source_clock_rejected(name):
    value = document()
    def omit(root):
        system = root.find("{%s}System" % NS)
        system.remove(system.find("{%s}%s" % (NS, name)))
    mutate_xml(value, omit)
    with pytest.raises(connector().ElasticParseError):
        parse(raw(value))


@pytest.mark.parametrize("field,value", [("event_id", "3"), ("record_id", "102"), ("provider_name", "Other"),
                                         ("channel", "Security"), ("computer_name", "other-host")])
def test_contradictory_winlog_identity_rejected(field, value):
    encoded = document()
    encoded["_source"]["winlog"][field] = value
    with pytest.raises(connector().ElasticParseError):
        parse(raw(encoded))


@pytest.mark.parametrize("field,value", [("pid", True), ("pid", 999), ("executable", "other.exe"), ("entity_id", "other-guid"),
                                         ("command_line", "other-command")])
def test_contradictory_process_alias_or_boolean_pid_rejected(field, value):
    encoded = document()
    encoded["_source"]["process"][field] = value
    with pytest.raises(connector().ElasticParseError):
        parse(raw(encoded))


@pytest.mark.parametrize("location,field,value", [("source", "port", True), ("source", "port", 65536),
                                                  ("destination", "ip", "203.0.113.2"), ("network", "transport", "udp")])
def test_contradictory_network_aliases_rejected(location, field, value):
    encoded = document("3")
    encoded["_source"][location][field] = value
    with pytest.raises(connector().ElasticParseError):
        parse(raw(encoded), "3")


@pytest.mark.parametrize("name,text", [("SourcePort", "65536"), ("DestinationPort", "-1"), ("ProcessId", "True"),
                                      ("SourceIp", "not-an-address"), ("Protocol", "sctp")])
def test_invalid_native_network_values_rejected(name, text):
    value = document("3")
    mutate_xml(value, lambda root: setattr(data_element(root, name), "text", text))
    with pytest.raises(connector().ElasticParseError):
        parse(raw(value), "3")


@pytest.mark.parametrize("field,text", [("MessageTotal", "2"), ("MessageNumber", "2"),
                                       ("ScriptBlockText", "  "), ("MessageTotal", "0")])
def test_incomplete_or_fragmented_script_rejected(field, text):
    value = document("4104")
    mutate_xml(value, lambda root: setattr(data_element(root, field), "text", text))
    with pytest.raises(connector().ElasticParseError):
        parse(raw(value), "4104")


def test_duplicate_json_and_xml_fields_rejected():
    encoded = raw(document())
    encoded = encoded.replace(b'"_id":"synthetic-document-101"', b'"_id":"one","_id":"two"')
    with pytest.raises(connector().ElasticParseError, match="duplicate_key"):
        parse(encoded)
    value = document()
    mutate_xml(value, lambda root: root.find("{%s}EventData" % NS).append(copy.deepcopy(data_element(root, "Image"))))
    with pytest.raises(connector().ElasticParseError):
        parse(raw(value))
    value = document()
    mutate_xml(value, lambda root: root.append(copy.deepcopy(root.find("{%s}System" % NS))))
    with pytest.raises(connector().ElasticParseError):
        parse(raw(value))


@pytest.mark.parametrize("xml", ["<Event/>", '<Event xmlns="urn:wrong"/>', "<broken",
                                '<!DOCTYPE Event [<!ENTITY x "EXPAND_ME">]><Event>&x;</Event>'])
def test_invalid_or_entity_xml_rejected(xml):
    value = document()
    value["_source"]["event"]["original"] = xml
    with pytest.raises(connector().ElasticParseError):
        parse(raw(value))


@pytest.mark.parametrize("key", ["_index", "_id", "_source"])
def test_required_export_envelope_identity(key):
    value = document()
    value.pop(key)
    with pytest.raises(connector().ElasticParseError):
        parse(raw(value))


@pytest.mark.parametrize("kind", ["event", "alert"])
def test_ambiguous_dotted_and_nested_alert_kind_rejected(kind):
    value = alert_document()
    value["_source"]["event"]["kind"] = kind
    with pytest.raises(connector().ElasticParseError):
        parse(raw(value), "alert")


@pytest.mark.parametrize("field,value", [("kibana.alert.start", None), ("kibana.alert.rule.rule_id", ""),
                                        ("kibana.alert.rule.revision", True), ("kibana.alert.ancestors", [{}])])
def test_malformed_alert_contract_rejected(field, value):
    encoded = alert_document()
    encoded["_source"][field] = value
    with pytest.raises(connector().ElasticParseError):
        parse(raw(encoded), "alert")


@pytest.mark.parametrize("field,value", [("kibana.alert.original_event.code", "3"),
                                        ("kibana.alert.original_event.provider", "Other"),
                                        ("kibana.alert.original_event.original", "<different-native/>")])
def test_copied_alert_identity_cannot_disagree_with_native_xml(field, value):
    encoded = alert_document()
    encoded["_source"][field] = value
    with pytest.raises(connector().ElasticParseError):
        parse(raw(encoded), "alert")


def test_alert_parameters_rule_id_must_agree_with_explicit_rule_identity():
    encoded = alert_document()
    encoded["_source"]["kibana.alert.rule.parameters"]["rule_id"] = "different-rule"
    with pytest.raises(connector().ElasticParseError):
        parse(raw(encoded), "alert")


def test_alert_original_event_kind_cannot_be_a_nested_signal():
    encoded = alert_document()
    encoded["_source"]["kibana.alert.original_event.kind"] = "signal"
    with pytest.raises(connector().ElasticParseError):
        parse(raw(encoded), "alert")


def test_wrong_native_profile_cannot_be_auto_dispatched():
    for source, target in [("3", "1"), ("1", "3"), ("4104", "1"), ("1", "4104")]:
        with pytest.raises(connector().ElasticParseError):
            parse(raw(document(source)), target)


def test_environment_claim_must_agree_with_context():
    with pytest.raises(connector().ElasticParseError):
        parse(raw(document()), environment_id="other-env")


@pytest.mark.parametrize("context", [{"source_ref": "../private"}, {"environment_id": " "},
                                    {"ingested_at": "2026-01-01T00:00:00"}])
def test_invalid_context_rejected(context):
    with pytest.raises(connector().ElasticParseError):
        parse(raw(document()), **context)


def test_exact_bytes_and_scope_are_part_of_event_identity():
    value = document()
    encoded = raw(value)
    first = parse(encoded).event
    assert parse(encoded + b"\n").event.event_id != first.event_id
    assert parse(encoded, source_ref="another-source").event.event_id != first.event_id
    value["_source"].pop("fields")
    assert parse(raw(value), environment_id="another-env").event.event_id != parse(raw(value)).event.event_id


def test_bounded_decoder_and_safe_diagnostics():
    module = connector()
    for encoded in [b"[]", b"{}{}", b"\xff", b" " * (256 * 1024 + 1),
                    b'{"_source":{"value":NaN}}', b'{"x":' + b"[" * 22 + b"0" + b"]" * 22 + b"}"]:
        with pytest.raises(module.ElasticParseError):
            parse(encoded)
    value = document()
    value["_source"]["winlog"]["event_id"] = "PRIVATE_SENTINEL_91"
    try:
        parse(raw(value))
    except module.ElasticParseError as error:
        printed = str(error) + repr(error.diagnostic) + "".join(traceback.format_exception(error))
        assert "PRIVATE_SENTINEL_91" not in printed
        assert "synthetic-endpoint" not in printed
        assert error.diagnostic.line is None or error.diagnostic.line > 0
    else:
        pytest.fail("contradictory private field was accepted")
