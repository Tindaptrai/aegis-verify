"""Bounded Windows XML mapping. XML facts never fall back to ECS guesses."""

from ipaddress import ip_address
import re
import xml.etree.ElementTree as ET

from aegis_verify.models import PreciseTimestamp

from .errors import ElasticParseError


NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_PREFIX = "{" + NS + "}"
_DECIMAL = re.compile(r"[0-9]{1,128}")
_UTC_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?")


def decimal(value, field, *, maximum=None):
    if value is None:
        return None
    if type(value) is not str or _DECIMAL.fullmatch(value) is None:
        raise ElasticParseError("invalid_field", field) from None
    number = int(value, 10)
    if maximum is not None and number > maximum:
        raise ElasticParseError("invalid_field", field) from None
    return number


def timestamp(value, field):
    if value is None:
        raise ElasticParseError("missing_event_time", field) from None
    if type(value) is not str:
        raise ElasticParseError("invalid_event_time", field) from None
    try:
        return PreciseTimestamp.parse(value)
    except (TypeError, ValueError):
        raise ElasticParseError("invalid_event_time", field) from None


class _BoundedTree(ET.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.nodes = 0

    def start(self, tag, attrs):
        self.depth += 1
        self.nodes += 1
        if self.depth > 20:
            raise ElasticParseError("max_depth", "event.original")
        if self.nodes > 10_000:
            raise ElasticParseError("max_nodes", "event.original")
        return super().start(tag, attrs)

    def end(self, tag):
        value = super().end(tag)
        self.depth -= 1
        return value

    def doctype(self, name, pubid, system):
        raise ElasticParseError("xml_entities_forbidden", "event.original")


def _unique(parent, field):
    result = {}
    for child in parent:
        if not child.tag.startswith(_PREFIX):
            raise ElasticParseError("invalid_xml_namespace", "event.original")
        name = child.tag[len(_PREFIX):]
        if name in result:
            raise ElasticParseError("duplicate_xml_field", field)
        result[name] = child
    return result


def _leaf(element, field, *, required=False):
    if element is None:
        if required:
            raise ElasticParseError("invalid_field", field)
        return None
    if len(element):
        raise ElasticParseError("invalid_xml", field)
    value = element.text or ""
    if required and not value.strip():
        raise ElasticParseError("invalid_field", field)
    return value


def parse_native(text, code):
    if type(text) is not str or not text.strip():
        raise ElasticParseError("invalid_field", "event.original")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.IGNORECASE):
        raise ElasticParseError("xml_entities_forbidden", "event.original")
    try:
        root = ET.fromstring(text, parser=ET.XMLParser(target=_BoundedTree()))
    except ET.ParseError:
        raise ElasticParseError("invalid_xml", "event.original") from None
    if root.tag != _PREFIX + "Event":
        raise ElasticParseError("invalid_xml_namespace", "event.original")
    if any(not node.tag.startswith(_PREFIX) for node in root.iter()):
        raise ElasticParseError("invalid_xml_namespace", "event.original")
    sections = _unique(root, "event.original")
    system = sections.get("System")
    if system is None:
        raise ElasticParseError("invalid_field", "windows.System")
    fields = _unique(system, "windows.System")
    provider_element = fields.get("Provider")
    provider = provider_element.get("Name") if provider_element is not None else None
    channel = _leaf(fields.get("Channel"), "windows.Channel", required=True)
    event_code = _leaf(fields.get("EventID"), "windows.EventID", required=True)
    expected = "Microsoft-Windows-PowerShell" if code == "4104" else "Microsoft-Windows-Sysmon"
    if provider != expected or channel != expected + "/Operational" or event_code != code:
        raise ElasticParseError("unsupported_profile", "windows.Provider")
    record_id = _leaf(fields.get("EventRecordID"), "windows.EventRecordID", required=True)
    decimal(record_id, "windows.EventRecordID")
    created = fields.get("TimeCreated")
    system_time = created.get("SystemTime") if created is not None else None
    event_time = timestamp(system_time, "windows.SystemTime")
    computer = _leaf(fields.get("Computer"), "windows.Computer")
    execution = fields.get("Execution")
    execution_pid = decimal(execution.get("ProcessID") if execution is not None else None,
                            "windows.Execution.ProcessID")
    data = {}
    if sections.get("EventData") is not None:
        for child in sections["EventData"]:
            if child.tag != _PREFIX + "Data" or not child.get("Name") or len(child):
                raise ElasticParseError("invalid_xml", "windows.EventData")
            name = child.get("Name")
            if name in data:
                raise ElasticParseError("duplicate_xml_field", "windows.EventData")
            data[name] = child.text or ""
    mapped = dict(timestamp=event_time, event_provider=provider, hostname=computer,
                  event_action="observed")
    metadata = dict(windows_event_id=code, windows_record_id=record_id,
                    windows_provider=provider, windows_channel=channel,
                    windows_system_time=system_time)
    if code == "4104":
        for name in ("MessageNumber", "MessageTotal"):
            value = data.get(name)
            if value is None:
                raise ElasticParseError("incomplete_script", "windows." + name)
            count = decimal(value, "windows." + name)
            if count != 1:
                raise ElasticParseError("unsupported_fragmentation", "windows." + name)
        if not data.get("ScriptBlockText", "").strip():
            raise ElasticParseError("incomplete_script", "windows.ScriptBlockText")
        mapped.update(process_id=execution_pid, file_path=data.get("Path"))
        metadata.update(script_block_id=data.get("ScriptBlockId"), message_number=1, message_total=1)
    else:
        mapped.update(process_id=decimal(data.get("ProcessId"), "windows.ProcessId"),
                      process_name=data.get("Image"), username=data.get("User"))
        metadata["process_guid"] = data.get("ProcessGuid")
        if data.get("UtcTime") is not None:
            utc = data["UtcTime"]
            if _UTC_TIME.fullmatch(utc) is None:
                raise ElasticParseError("invalid_event_time", "windows.UtcTime")
            utc_time = timestamp(utc.replace(" ", "T") + "Z", "windows.UtcTime")
            metadata.update(sysmon_utc_time=utc, sysmon_clock_delta_ns=event_time.difference_ns(utc_time))
        if code == "1":
            mapped.update(parent_process_name=data.get("ParentImage"), command_line=data.get("CommandLine"))
            metadata.update(parent_process_guid=data.get("ParentProcessGuid"),
                            parent_process_id=decimal(data.get("ParentProcessId"), "windows.ParentProcessId"))
        else:
            protocol = data.get("Protocol")
            if protocol is not None and protocol not in {"tcp", "udp"}:
                raise ElasticParseError("unsupported_profile", "windows.Protocol")
            mapped["protocol"] = protocol
            for source_key, canonical in (("SourceIp", "src_ip"), ("DestinationIp", "dst_ip")):
                value = data.get(source_key)
                if value is not None:
                    try:
                        value = ip_address(value)
                    except ValueError:
                        raise ElasticParseError("invalid_field", "windows." + source_key) from None
                mapped[canonical] = value
            mapped.update(src_port=decimal(data.get("SourcePort"), "windows.SourcePort", maximum=65535),
                          dst_port=decimal(data.get("DestinationPort"), "windows.DestinationPort", maximum=65535))
    return mapped, metadata, data, execution_pid
