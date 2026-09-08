"""Suricata alert mapping only; no collector wrapper or live-system access."""
import re

from aegis_verify.models import PreciseTimestamp

from ._fields import address, decimal_id, flow_id, number, object_field, text
from .errors import SuricataParseError


def map_alert(data: dict) -> tuple[dict, dict]:
    prefix = '_source.data.'
    alert = object_field(data.get('alert'), prefix + 'alert')
    raw_time = data.get('timestamp')
    if raw_time is None:
        raise SuricataParseError('missing_event_time', prefix + 'timestamp')
    try:
        if type(raw_time) is not str:
            raise ValueError
        timestamp = PreciseTimestamp.parse(re.sub(r'([+-][0-9]{2})([0-9]{2})$', r'\1:\2', raw_time))
    except (ValueError, TypeError, OverflowError):
        raise SuricataParseError('invalid_event_time', prefix + 'timestamp') from None

    action = text(alert.get('action'), prefix + 'alert.action')
    if action is not None and action not in ('allowed', 'blocked'):
        raise SuricataParseError('invalid_field', prefix + 'alert.action')
    sid = decimal_id(alert.get('signature_id'), prefix + 'alert.signature_id')
    event = dict(source_type='suricata', event_provider='suricata', timestamp=timestamp,
                 signature_id=sid, event_action=action,
                 severity=number(alert.get('severity'), prefix + 'alert.severity'),
                 protocol=text(data.get('proto'), prefix + 'proto'))
    for source, target in (('src_ip', 'src_ip'), ('dest_ip', 'dst_ip')):
        event[target] = address(data.get(source), prefix + source)
    for source, target in (('src_port', 'src_port'), ('dest_port', 'dst_port')):
        event[target] = number(data.get(source), prefix + source, maximum=65535)
    metadata = dict(source_fraction_digits=timestamp.fractional_digits,
                    signature_id=sid, source_alert_action=action,
                    flow_id_raw=flow_id(data.get('flow_id'), prefix + 'flow_id'))
    for source, target in (('gid', 'signature_gid'), ('rev', 'signature_rev')):
        metadata[target] = decimal_id(alert.get(source), prefix + 'alert.' + source)
    for source, target in (('signature', 'signature_text'), ('category', 'signature_category')):
        metadata[target] = text(alert.get(source), prefix + 'alert.' + source)
    for key in ('app_proto', 'in_iface'):
        metadata[key] = text(data.get(key), prefix + key)
    return event, metadata
