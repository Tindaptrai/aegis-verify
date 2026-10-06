"""Pinned Snort 3 alert_json fields to canonical facts; absent stays null, nothing inferred."""
from datetime import datetime, timezone
from ipaddress import ip_address
import re

from aegis_verify.models import PreciseTimestamp

from .errors import PINNED_FIELDS, SnortParseError

PORT_PROTOCOLS = ('TCP', 'UDP')
_ADDRESSES = ('src_addr', 'dst_addr')
_PORTS = ('src_port', 'dst_port')
_U32 = 2**32 - 1
_U64 = 2**64 - 1
_MAX_SECONDS = 4102444799  # 2099-12-31T23:59:59Z: show_year prints a two-digit year
_PROTO = re.compile(r'[A-Z][A-Z0-9]{0,15}')
_GEN = re.compile(r'[a-z][a-z0-9_]{0,31}')
_DIR = re.compile(r'C2S|S2C|UNK')
_TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}')
_RULE = re.compile(r'([0-9]{1,10}):([0-9]{1,10}):([0-9]{1,10})')
# output.show_year = true and process.utc = true: YY/MM/DD-hh:mm:ss.uuuuuu in UTC.
_STAMP = re.compile(r'([0-9]{2})/([0-9]{2})/([0-9]{2})-([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{6})')
_STAMP_NO_YEAR = re.compile(r'[0-9]{2}/[0-9]{2}-[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}')
# Every action string Snort 3.12 can print. Only definite packet outcomes are mapped;
# would_*, cant_*, rewrite, hold, retry and error stay null (raw value kept in provenance).
ACTIONS = {
    'allow': 'allowed', 'trust': 'allowed',
    'drop': 'blocked', 'block': 'blocked', 'reset': 'blocked',
    'force_drop': 'blocked', 'force_block': 'blocked', 'force_reset': 'blocked',
    **dict.fromkeys(('hold', 'retry', 'rewrite', 'cant_rewrite', 'would_rewrite', 'force_rewrite',
                     'cant_drop', 'would_drop', 'cant_block', 'would_block',
                     'cant_reset', 'would_reset', 'error')),
}


def _integer(data, key, maximum):
    value = data[key]
    if type(value) is not int or not 0 <= value <= maximum:
        raise SnortParseError('invalid_field', key)
    return value


def _text(data, key, *, pattern=None, max_len=4096):
    value = data[key]
    if type(value) is not str or not value or len(value) > max_len:
        raise SnortParseError('invalid_field', key)
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        raise SnortParseError('invalid_field', key) from None
    if pattern is not None and not pattern.fullmatch(value):
        raise SnortParseError('invalid_field', key)
    return value


def _address(data, key):
    value = _text(data, key, max_len=64)
    try:
        if '%' in value:
            raise ValueError
        return ip_address(value)
    except ValueError:
        raise SnortParseError('invalid_field', key) from None


def _check_profile(data):
    """The pinned list, in order; only addresses (no IP header) and ports (not TCP/UDP) may be absent."""
    keys = tuple(data)
    for key in keys:
        if key not in PINNED_FIELDS:
            raise SnortParseError('unsupported_profile')
    if keys != tuple(k for k in PINNED_FIELDS if k in data):
        raise SnortParseError('unsupported_profile')
    for key in PINNED_FIELDS:
        if key not in data and key not in _ADDRESSES + _PORTS:
            raise SnortParseError('unsupported_profile', key)


def _event_time(data):
    seconds = data['seconds']
    if type(seconds) is not int or not 0 <= seconds <= _MAX_SECONDS:
        raise SnortParseError('invalid_event_time', 'seconds')
    text = data['timestamp']
    if type(text) is not str:
        raise SnortParseError('invalid_event_time', 'timestamp')
    match = _STAMP.fullmatch(text)
    if match is None:
        if _STAMP_NO_YEAR.fullmatch(text):
            raise SnortParseError('unsupported_profile', 'timestamp')
        raise SnortParseError('invalid_event_time', 'timestamp')
    year, month, day, hour, minute, second, micros = match.groups()
    try:
        shown = datetime(2000 + int(year), int(month), int(day), int(hour), int(minute), int(second),
                         tzinfo=timezone.utc)
    except ValueError:
        raise SnortParseError('invalid_event_time', 'timestamp') from None
    if int(shown.timestamp()) != seconds:
        # Not the same UTC second: the sensor was not running with process.utc = true.
        raise SnortParseError('invalid_event_time', 'timestamp')
    return seconds, PreciseTimestamp.parse(shown.strftime('%Y-%m-%dT%H:%M:%S.') + micros + 'Z')


def map_alert(data: dict) -> tuple[dict, dict, bool]:
    """Return (canonical fields, provenance metadata, has_ip_header) for one alert_json object."""
    _check_profile(data)
    seconds, timestamp = _event_time(data)
    proto = _text(data, 'proto', pattern=_PROTO, max_len=16)
    has_ports = proto in PORT_PROTOCOLS
    for key in _PORTS:
        if (key in data) != has_ports:
            raise SnortParseError('invalid_field', key)
    has_ip = 'src_addr' in data
    if ('dst_addr' in data) != has_ip:
        raise SnortParseError('invalid_field', 'dst_addr')
    match = _RULE.fullmatch(_text(data, 'rule', max_len=32))
    if match is None or any(int(part) > _U32 for part in match.groups()):
        raise SnortParseError('invalid_field', 'rule')
    gid, sid, rev = (str(int(part)) for part in match.groups())
    action = _text(data, 'action', max_len=32)
    if action not in ACTIONS:
        raise SnortParseError('invalid_field', 'action')
    priority = _integer(data, 'priority', _U32)
    event = dict(
        source_type='snort', event_provider='snort', timestamp=timestamp, protocol=proto,
        src_ip=_address(data, 'src_addr') if has_ip else None,
        dst_ip=_address(data, 'dst_addr') if has_ip else None,
        src_port=_integer(data, 'src_port', 65535) if has_ports else None,
        dst_port=_integer(data, 'dst_port', 65535) if has_ports else None,
        signature_id=sid, event_action=ACTIONS[action],
        # Snort prints priority 0 when no classtype/priority is set: absent, not a rank.
        severity=priority or None,
    )
    metadata = dict(
        source_seconds=seconds, source_fraction_digits=timestamp.fractional_digits,
        signature_id=sid, signature_gid=gid, signature_rev=rev,
        signature_text=_text(data, 'msg'), signature_category=_text(data, 'class', max_len=256),
        app_proto=_text(data, 'service', pattern=_TOKEN, max_len=64),
        direction=_text(data, 'dir', pattern=_DIR, max_len=3),
        pkt_gen=_text(data, 'pkt_gen', pattern=_GEN, max_len=32),
        pkt_len=_integer(data, 'pkt_len', _U32), pkt_num=_integer(data, 'pkt_num', _U64),
        source_alert_action=action, source_priority=priority,
    )
    return event, metadata, has_ip
