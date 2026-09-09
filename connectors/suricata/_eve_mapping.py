"""Direct EVE semantics; shared source mapping never reads Wazuh selectors."""
from ._fields import object_field, text
from ._mapping import map_alert, map_network, source_time
from .errors import SuricataParseError


def direct_integer(value, path, maximum=10**128 - 1):
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= maximum:
        raise SuricataParseError('invalid_field', path)
    return value


def map_eve(data: dict, kind: str) -> tuple[dict, dict]:
    # A permits integral decimal strings; direct EVE's ID is a JSON integer.
    fid = direct_integer(data.get('flow_id'), 'flow_id')
    if kind == 'alert':
        event, metadata = map_alert(data, prefix='')
    else:
        event = map_network(data, '')
        metadata = dict(source_fraction_digits=event['timestamp'].fractional_digits,
                        app_proto=text(data.get('app_proto'), 'app_proto'),
                        in_iface=text(data.get('in_iface'), 'in_iface'))
    metadata.update(flow_id_raw=str(fid) if fid is not None else None,
                    action_scope='alert_rule' if kind == 'alert' else 'flow',
                    source_src_port=event['src_port'], source_dst_port=event['dst_port'],
                    icmp_type=direct_integer(data.get('icmp_type'), 'icmp_type', 255),
                    icmp_code=direct_integer(data.get('icmp_code'), 'icmp_code', 255))
    if event['protocol'] is not None and event['protocol'].upper() in ('ICMP', 'ICMPV6', 'IPV6-ICMP'):
        event.update(src_port=None, dst_port=None)
    flow = object_field(data.get('flow'), 'flow', optional=kind == 'alert')
    for key in ('start', 'end'):
        value = flow.get(key)
        metadata['flow_' + key] = source_time(value, 'flow.' + key) if value is not None else None
    for key in ('pkts_toserver', 'pkts_toclient', 'bytes_toserver', 'bytes_toclient'):
        metadata['flow_' + key] = direct_integer(flow.get(key), 'flow.' + key)
    for key in ('state', 'reason'):
        metadata['flow_' + key] = text(flow.get(key), 'flow.' + key)
    alerted = flow.get('alerted')
    if alerted is not None and type(alerted) is not bool:
        raise SuricataParseError('invalid_field', 'flow.alerted')
    metadata['flow_alerted'] = alerted
    action = text(flow.get('action'), 'flow.action')
    if action is not None and action not in ('pass', 'drop'):
        raise SuricataParseError('invalid_field', 'flow.action')
    metadata['source_flow_action'] = action
    if kind == 'flow':
        event['event_action'] = {'pass': 'allowed', 'drop': 'blocked', None: None}[action]
    return event, metadata
