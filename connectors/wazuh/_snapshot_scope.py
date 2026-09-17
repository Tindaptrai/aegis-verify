"""Scope decisions use only declared metadata, never expected detection content."""

import re

from aegis_verify.models import PreciseTimestamp
from ._snapshot_contracts import ManagerSnapshotError, ManagerSnapshotScope


PROFILES = {
    ('Microsoft-Windows-Sysmon', '1'): 'wazuh-sysmon1-v1',
    ('Microsoft-Windows-PowerShell', '4104'): 'wazuh-powershell4104-v1',
}


def valid_text(value, max_bytes=4096):
    if type(value) is not str or not value.strip():
        return False
    try:
        return len(value.encode('utf-8')) <= max_bytes
    except UnicodeEncodeError:
        return False


def validate_scope(scope):
    if type(scope) is not ManagerSnapshotScope or not all(
        valid_text(getattr(scope, key, None), limit) for key, limit in
        (('agent_id', 128), ('hostname', 4096), ('environment_id', 128),
         ('start', 35), ('end', 35), ('ingested_at', 35))
    ):
        raise ManagerSnapshotError('invalid_context')
    try:
        start, end, ingestion = (PreciseTimestamp.parse(getattr(scope, key))
                                  for key in ('start', 'end', 'ingested_at'))
    except ValueError:
        raise ManagerSnapshotError('invalid_context') from None
    if start > end:
        raise ManagerSnapshotError('invalid_context')
    return start, end, ingestion


def classify(record, scope, start, end):
    """Return (parser key or None, reason); uncertainty raises, not excludes."""
    def fail():
        raise ManagerSnapshotError('unclassifiable_record')

    agent = record.get('agent')
    if type(agent) is not dict or not valid_text(agent.get('id')):
        fail()
    if agent['id'] != scope.agent_id:
        return None, 'outside_agent'

    decoder = record.get('decoder')
    decoder_name = decoder.get('name') if type(decoder) is dict else None
    data = record.get('data')
    has_win = type(data) is dict and 'win' in data
    if not has_win:
        if (data is None or type(data) is dict) and valid_text(decoder_name) and decoder_name != 'windows_eventchannel':
            return None, 'outside_event'
        fail()
    if decoder_name != 'windows_eventchannel':
        fail()
    win = data['win']
    system = win.get('system') if type(win) is dict else None
    if type(system) is not dict or not valid_text(system.get('computer')):
        fail()
    if system['computer'] != scope.hostname:
        return None, 'outside_host'
    provider, event_code = system.get('providerName'), system.get('eventID')
    if not valid_text(provider) or type(event_code) is not str or re.fullmatch(r'[0-9]{1,128}', event_code) is None:
        fail()
    parser = PROFILES.get((provider, event_code))
    if parser is None:
        return None, 'outside_event'
    try:
        stamp = PreciseTimestamp.parse(system.get('systemTime'))
    except (TypeError, ValueError):
        fail()
    if stamp < start or stamp > end:
        return None, 'outside_window'
    return parser, 'supported_windows_event'
