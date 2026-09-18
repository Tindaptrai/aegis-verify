"""Synthetic-only tests: manager snapshot bytes, not a live collection claim."""

from dataclasses import replace
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys

import pytest


FIXTURES = Path(__file__).resolve().parents[2] / 'tests/fixtures/wazuh/windows-telemetry'


@pytest.fixture
def api():
    return importlib.import_module('aegis_verify.connectors.wazuh.manager_snapshot')


@pytest.fixture
def scope(api):
    return api.ManagerSnapshotScope(
        agent_id='901', hostname='synthetic-endpoint', environment_id='synthetic-env',
        start='2026-01-01T00:00:00Z', end='2026-01-01T00:02:00Z',
        ingested_at='2026-01-01T00:03:00Z',
    )


def source(kind='sysmon1'):
    obj = json.loads((FIXTURES / (kind + '.synthetic.json')).read_bytes())['_source']
    obj['decoder'] = {'name': 'windows_eventchannel'}
    return obj


def wire(obj):
    return json.dumps(obj, ensure_ascii=True, separators=(',', ':')).encode('utf-8')


def snapshot(api, raw, label='synthetic-day'):
    return api.ManagerSnapshot(source_label=label, raw=raw, sha256=hashlib.sha256(raw).hexdigest())


def parse(api, scope, raw):
    return api.parse_manager_snapshots((snapshot(api, raw),), scope=scope)


def test_wrapped_bytes_keep_unknown_number_lexeme_and_real_parser_identity(api, scope):
    # Re-serialization would change 1.2300e+02 and source whitespace.
    body = wire(source())[:-1] + b', "synthetic_unknown":1.2300e+02}'
    result = parse(api, scope, body + b'\r\n')
    doc = result.documents[0]
    assert doc.raw == b'{"_source":' + body + b'}'
    assert doc.source_ref == 'synthetic-day-line-1'
    assert doc.parser == 'wazuh-sysmon1-v1'
    assert doc.telemetry.event.process_id == 4242
    assert doc.telemetry.event.timestamp.isoformat() == '2026-01-01T00:00:01.123456789Z'
    digest = hashlib.sha256(doc.raw).hexdigest()
    identity = json.dumps(['wazuh-evidence-v1', 'synthetic-env', 'synthetic-day-line-1', 1, digest],
                          ensure_ascii=True, separators=(',', ':')).encode()
    assert doc.telemetry.event.event_id == 'wazuh:evidence-v1:' + hashlib.sha256(identity).hexdigest()
    assert doc.telemetry.event.raw_event_hash == digest
    assert doc.telemetry.event.raw_event_ref == 'synthetic-day-line-1#record=1'
    row = result.ledger[0]
    assert (row.line, row.byte_offset, row.byte_length) == (1, 0, len(body) + 2)
    assert row.line_sha256 == hashlib.sha256(body + b'\r\n').hexdigest()
    assert row.document_sha256 == digest
    assert row.document_source_ref == doc.source_ref
    assert (row.disposition, row.reason) == ('selected', 'supported_windows_event')


@pytest.mark.parametrize('ending', [b'\n', b'\r\n', b''])
def test_line_endings_and_first_bom_have_exact_coordinates(api, scope, ending):
    body = wire(source())
    raw = b'\xef\xbb\xbf' + body + ending
    result = parse(api, scope, raw)
    assert result.documents[0].raw == b'{"_source":' + body + b'}'
    row = result.ledger[0]
    assert row.bom_removed is True
    assert row.byte_length == len(raw)
    assert row.line_sha256 == hashlib.sha256(raw).hexdigest()
    assert result.snapshots[0].sha256 == hashlib.sha256(raw).hexdigest()
    assert result.snapshots[0].byte_length == len(raw)
    assert result.snapshots[0].line_count == 1


def test_blank_lines_preserved_in_ledger_not_as_events(api, scope):
    a, b = wire(source()), wire(source('powershell4104'))
    raw = b' \r\n' + a + b'\n\n' + b
    result = parse(api, scope, raw)
    assert len(result.ledger) == 4
    assert [r.disposition for r in result.ledger] == ['bookkeeping', 'selected', 'bookkeeping', 'selected']
    assert [r.byte_offset for r in result.ledger] == [0, 3, 4 + len(a), 5 + len(a)]
    assert [d.source_ref for d in result.documents] == ['synthetic-day-line-2', 'synthetic-day-line-4']
    assert result.documents[1].parser == 'wazuh-powershell4104-v1'
    assert result.documents[1].telemetry.event.command_line is None
    assert result.ledger[0].document_sha256 is None


def test_generic_rules_wrong_pid_and_unrelated_script_are_not_export_filters(api, scope):
    obj = source('powershell4104')
    obj['rule'] = {'id': '91816', 'level': 4}
    obj['data']['win']['system']['processID'] = '5555'
    obj['data']['win']['eventdata']['path'] = 'synthetic-other.ps1'
    obj['data']['win']['eventdata']['scriptBlockText'] = 'synthetic unrelated text'
    result = parse(api, scope, wire(obj))
    event = result.documents[0].telemetry.event
    assert (event.rule_id, event.process_id, event.file_path) == ('91816', 5555, 'synthetic-other.ps1')


def test_absent_optional_pid_stays_null_not_filled_from_scope(api, scope):
    obj = source()
    del obj['data']['win']['eventdata']['processId']
    assert parse(api, scope, wire(obj)).documents[0].telemetry.event.process_id is None


@pytest.mark.parametrize(('section', 'key', 'value', 'reason'), [
    ('agent', 'id', '902', 'outside_agent'),
    ('system', 'computer', 'synthetic-other', 'outside_host'),
    ('system', 'providerName', 'Synthetic-Other-Provider', 'outside_event'),
    ('system', 'eventID', '2', 'outside_event'),
    ('system', 'systemTime', '2025-12-31T23:59:59.999999999Z', 'outside_window'),
    ('system', 'systemTime', '2026-01-01T00:02:00.000000001Z', 'outside_window'),
])
def test_proven_outside_scope_is_audited(api, scope, section, key, value, reason):
    obj = source()
    target = obj[section] if section == 'agent' else obj['data']['win']['system']
    target[key] = value
    result = parse(api, scope, wire(obj))
    assert result.documents == ()
    assert (result.ledger[0].disposition, result.ledger[0].reason) == ('excluded', reason)


@pytest.mark.parametrize('stamp', ['2026-01-01T00:00:00Z', '2026-01-01T00:02:00Z',
                                   '2026-01-01T07:02:00+07:00'])
def test_closed_window_and_offsets_are_exact(api, scope, stamp):
    obj = source()
    obj['data']['win']['system']['systemTime'] = stamp
    assert len(parse(api, scope, wire(obj)).documents) == 1


@pytest.mark.parametrize(('section', 'key'), [('agent', 'id'), ('system', 'computer'),
    ('system', 'providerName'), ('system', 'eventID'), ('system', 'systemTime')])
def test_missing_classification_metadata_is_not_silently_excluded(api, scope, section, key):
    obj = source()
    target = obj[section] if section == 'agent' else obj['data']['win']['system']
    del target[key]
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(obj))
    assert caught.value.diagnostic.code == 'unclassifiable_record'
    assert caught.value.diagnostic.line == 1


def test_proven_non_windows_record_is_excluded_without_fabricated_windows_fields(api, scope):
    obj = {'id': 'synthetic-pam', 'agent': {'id': '901'}, 'decoder': {'name': 'pam'}}
    result = parse(api, scope, wire(obj))
    assert result.documents == ()
    assert result.ledger[0].reason == 'outside_event'


@pytest.mark.parametrize('patch', [
    {'messageNumber': '2', 'messageTotal': '2'},
    {'messageTotal': None}, {'scriptBlockText': ''}, {'scriptBlockText': None},
])
def test_selected_incomplete_or_fragmented_ps_stops_entire_snapshot(api, scope, patch):
    obj = source('powershell4104')
    obj['data']['win']['eventdata'].update(patch)
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(source()) + b'\n' + wire(obj))
    assert caught.value.diagnostic.code == 'parser_error'
    assert caught.value.diagnostic.line == 2
    assert caught.value.diagnostic.parser_code in {'incomplete_script', 'unsupported_fragmentation'}


@pytest.mark.parametrize('bad', [b'{"PRIVATE_CANARY":', b'[]', b'{"a":1,"a":2}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'{"x":"\xff"}',
    b'{"x":"\\ud800"}', b'{"_source":{}}', b'{}{}'])
def test_invalid_record_fails_without_leaking_raw_value(api, scope, bad):
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(source()) + b'\n' + bad)
    assert caught.value.diagnostic.code == 'invalid_record'
    assert caught.value.diagnostic.line == 2
    assert 'PRIVATE_CANARY' not in str(caught.value)


def test_bom_on_second_line_rejected(api, scope):
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(source()) + b'\n\xef\xbb\xbf' + wire(source('powershell4104')))
    assert caught.value.diagnostic.code == 'invalid_record'


def test_hash_checked_before_content_is_parsed(api, scope):
    item = api.ManagerSnapshot('synthetic-day', b'{broken', '0' * 64)
    with pytest.raises(api.ManagerSnapshotError) as caught:
        api.parse_manager_snapshots((item,), scope=scope)
    assert caught.value.diagnostic.code == 'hash_mismatch'


@pytest.mark.parametrize(('field', 'value'), [
    ('agent_id', ''), ('hostname', ''), ('environment_id', ''),
    ('agent_id', 901), ('start', '2026-01-01'), ('end', '2025-01-01T00:00:00Z'),
    ('ingested_at', 'unknown'),
])
def test_invalid_context_rejected_even_for_empty_snapshot(api, scope, field, value):
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, replace(scope, **{field: value}), b'')
    assert caught.value.diagnostic.code == 'invalid_context'


@pytest.mark.parametrize('label', ['', '../private', 'a/b', 'a\\b', 'a' * 117, 7])
def test_source_labels_fit_derived_ref_and_cannot_be_paths(api, scope, label):
    with pytest.raises(api.ManagerSnapshotError) as caught:
        api.parse_manager_snapshots((snapshot(api, wire(source()), label),), scope=scope)
    assert caught.value.diagnostic.code == 'invalid_input'


def test_duplicate_record_id_does_not_create_extra_evidence(api, scope):
    a, b = source(), source()
    b['rule']['id'] = 'different-rule'
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(a) + b'\n' + wire(b))
    assert caught.value.diagnostic.code == 'duplicate_record'


def test_duplicate_id_from_different_managers_kept_distinct(api, scope):
    a, b = source(), source()
    b['manager']['name'] = 'synthetic-other-manager'
    assert len(parse(api, scope, wire(a) + b'\n' + wire(b)).documents) == 2


def test_duplicate_record_across_files_rejected(api, scope):
    a, b = source(), source()
    b['rule']['level'] = 4
    with pytest.raises(api.ManagerSnapshotError) as caught:
        api.parse_manager_snapshots((snapshot(api, wire(a), 'a'), snapshot(api, wire(b), 'b')), scope=scope)
    assert caught.value.diagnostic.code == 'duplicate_record'
    assert caught.value.diagnostic.snapshot_index == 1


def test_duplicate_snapshot_and_label_rejected(api, scope):
    a = snapshot(api, wire(source()))
    for items in ((a, replace(a, source_label='other')),
                  (a, snapshot(api, wire(source('powershell4104'))))):
        with pytest.raises(api.ManagerSnapshotError) as caught:
            api.parse_manager_snapshots(items, scope=scope)
        assert caught.value.diagnostic.code == 'duplicate_snapshot'


def test_stable_identity_when_snapshot_input_order_changes(api, scope):
    a, b = snapshot(api, wire(source()), 'a'), snapshot(api, wire(source('powershell4104')), 'b')
    first = api.parse_manager_snapshots((a, b), scope=scope)
    second = api.parse_manager_snapshots((b, a), scope=scope)
    assert {d.source_ref: d.telemetry.event.event_id for d in first.documents} == {
        d.source_ref: d.telemetry.event.event_id for d in second.documents}


def test_101_selected_records_are_not_truncated_to_cli_limit(api, scope):
    rows = []
    for i in range(101):
        obj = source()
        # A different archive id alone would leave 101 copies of one event, which
        # is a duplicate rather than a distinct record. Vary the event too.
        obj['id'] = 'synthetic-' + str(i)
        obj['data']['win']['system']['eventRecordID'] = str(1000 + i)
        rows.append(wire(obj))
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, b'\n'.join(rows))
    assert caught.value.diagnostic.code == 'resource_limit'


def test_too_many_physical_lines_including_blank_lines(api, scope):
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, b'\n' * 20_001)
    assert caught.value.diagnostic.code == 'resource_limit'


def test_wrapping_overhead_counts_toward_parser_size_limit(api, scope):
    body = wire(source())
    body = body + b' ' * (256 * 1024 - len(body))
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, body)
    assert caught.value.diagnostic.code == 'resource_limit'


def test_empty_snapshot_has_no_events_not_a_completeness_claim(api, scope):
    result = parse(api, scope, b'')
    assert result.documents == result.ledger == ()
    assert result.snapshots[0].line_count == 0
    assert result.collection_assurance == 'unknown'


@pytest.mark.parametrize(('section', 'key', 'value'), [
    ('system', 'computer', None), ('system', 'providerName', []),
    ('system', 'eventID', 1), ('system', 'eventID', '١'),
    ('system', 'systemTime', '2026-01-01T00:00:01-00:00'),
    ('system', 'systemTime', '2026-01-01T00:00:01.1234567890Z'),
    ('agent', 'id', True), ('agent', 'id', []),
])
def test_invalid_classification_field_types_and_times_raise(api, scope, section, key, value):
    obj = source()
    target = obj[section] if section == 'agent' else obj['data']['win']['system']
    target[key] = value
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(obj))
    assert caught.value.diagnostic.code == 'unclassifiable_record'


@pytest.mark.parametrize('decoder', [None, {}, {'name': 'json'}, {'name': 'pam'}])
def test_decoder_conflict_cannot_hide_windows_fields(api, scope, decoder):
    obj = source()
    obj['decoder'] = decoder
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(obj))
    assert caught.value.diagnostic.code == 'unclassifiable_record'


@pytest.mark.parametrize('part', [None, [], 'synthetic', True])
def test_missing_or_malformed_win_cannot_be_assumed_non_windows(api, scope, part):
    obj = source()
    obj['data']['win'] = part
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(obj))
    assert caught.value.diagnostic.code == 'unclassifiable_record'


def test_selected_wrong_channel_is_not_a_successful_skip(api, scope):
    obj = source()
    obj['data']['win']['system']['channel'] = 'Security'
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(obj))
    assert (caught.value.diagnostic.code, caught.value.diagnostic.parser_code) == ('parser_error', 'unsupported_profile')


@pytest.mark.parametrize('bad', [
    b'{"x":' + b'[' * 21 + b'0' + b']' * 21 + b'}',
    b'{"x":[' + b'0,' * 10_000 + b'0]}',
    b'{"x":' + b'1' * 129 + b'}',
])
def test_bounded_decoder_errors_are_reported_as_invalid_records(api, scope, bad):
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, bad)
    assert caught.value.diagnostic.code == 'invalid_record'
    assert caught.value.diagnostic.parser_code in {'max_depth', 'max_nodes', 'invalid_number'}


def test_wrapper_added_depth_respects_real_parser_limit(api, scope):
    obj = source()
    nested = 1
    for _ in range(19):
        nested = [nested]
    obj['unknown_synthetic'] = nested  # body depth20; wrapped depth21.
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(obj))
    assert (caught.value.diagnostic.code, caught.value.diagnostic.parser_code) == ('parser_error', 'max_depth')


@pytest.mark.parametrize('items', [None, [], {}, (None,), (b'{}',)])
def test_invalid_snapshot_container_or_item_rejected(api, scope, items):
    with pytest.raises(api.ManagerSnapshotError) as caught:
        api.parse_manager_snapshots(items, scope=scope)
    assert caught.value.diagnostic.code == 'invalid_input'


@pytest.mark.parametrize(('field', 'value'), [('raw', 'not bytes'), ('raw', bytearray(b'{}')),
    ('sha256', 'A' * 64), ('sha256', 4), ('sha256', '1' * 63)])
def test_invalid_snapshot_contract_values_rejected(api, scope, field, value):
    item = replace(snapshot(api, wire(source())), **{field: value})
    with pytest.raises(api.ManagerSnapshotError) as caught:
        api.parse_manager_snapshots((item,), scope=scope)
    assert caught.value.diagnostic.code == 'invalid_input'


@pytest.mark.parametrize('field', ['agent_id', 'hostname', 'environment_id'])
def test_surrogate_in_context_is_sanitized_even_without_records(api, scope, field):
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, replace(scope, **{field: 'PRIVATE_CANARY\ud800'}), b'')
    assert caught.value.diagnostic.code == 'invalid_context'
    assert 'PRIVATE_CANARY' not in str(caught.value)


def test_context_wrong_object_type_rejected(api):
    with pytest.raises(api.ManagerSnapshotError) as caught:
        api.parse_manager_snapshots((), scope={})
    assert caught.value.diagnostic.code == 'invalid_context'


def test_33_snapshots_rejected_before_parsing_any(api, scope):
    items = tuple(snapshot(api, b'\n' * i, 'synthetic-' + str(i)) for i in range(33))
    with pytest.raises(api.ManagerSnapshotError) as caught:
        api.parse_manager_snapshots(items, scope=scope)
    assert caught.value.diagnostic.code == 'resource_limit'


def test_file_and_total_byte_caps_checked_before_json_parse(api, scope, monkeypatch):
    # Shrink resource caps only, not parsing/hashing behavior.
    monkeypatch.setattr(api, 'MAX_SNAPSHOT_BYTES', 10)
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, b' ' * 11)
    assert caught.value.diagnostic.code == 'resource_limit'
    monkeypatch.setattr(api, 'MAX_TOTAL_BYTES', 15)
    items = (snapshot(api, b' ' * 8, 'a'), snapshot(api, b'\t' * 8, 'b'))
    with pytest.raises(api.ManagerSnapshotError) as caught:
        api.parse_manager_snapshots(items, scope=scope)
    assert caught.value.diagnostic.code == 'resource_limit'


def test_global_line_cap_spans_snapshots_not_per_file(api, scope):
    items = (snapshot(api, b'\n' * 10_000, 'a'), snapshot(api, b' \n' * 10_001, 'b'))
    with pytest.raises(api.ManagerSnapshotError) as caught:
        api.parse_manager_snapshots(items, scope=scope)
    assert caught.value.diagnostic.code == 'resource_limit'
    assert (caught.value.diagnostic.snapshot_index, caught.value.diagnostic.line) == (1, 10_001)


def test_limit_of_100_selected_documents_is_accepted(api, scope):
    records = []
    for i in range(100):
        obj = source()
        obj['id'] = 'synthetic-' + str(i)
        obj['data']['win']['system']['eventRecordID'] = str(1000 + i)
        records.append(wire(obj))
    assert len(parse(api, scope, b'\n'.join(records)).documents) == 100


def test_longest_label_and_final_line_still_have_valid_evidence_ref(api, scope):
    label = 's' * 116
    raw = b'\n' * 19_999 + wire(source())
    result = api.parse_manager_snapshots((snapshot(api, raw, label),), scope=scope)
    assert result.documents[0].source_ref == label + '-line-20000'
    assert len(result.documents[0].source_ref) <= 128


def test_absent_source_id_does_not_get_fabricated_from_line_number(api, scope):
    obj = source()
    del obj['id']
    result = parse(api, scope, wire(obj))
    assert result.documents[0].telemetry.event.source_record_id is None
    assert result.ledger[0].source_record_id is None


def test_identical_body_without_source_id_is_rejected_even_with_changed_newline(api, scope):
    obj = source()
    del obj['id']
    body = wire(obj)
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, body + b'\r\n' + body + b'\n')
    assert caught.value.diagnostic.code == 'duplicate_record'


def test_snapshot_repr_does_not_echo_raw_payload(api):
    item = snapshot(api, b'PRIVATE_CANARY')
    assert 'PRIVATE_CANARY' not in repr(item)


def test_error_constructor_does_not_echo_arbitrary_diagnostics(api):
    error = api.ManagerSnapshotError('PRIVATE_CANARY', snapshot_index=True,
                                     line=-1, parser_code='PRIVATE_CANARY')
    assert str(error) == 'invalid_input'
    assert error.diagnostic.snapshot_index is None
    assert error.diagnostic.line is None
    assert error.diagnostic.parser_code is None


def test_wrapped_documents_run_through_existing_cli_without_claiming_gap(api, scope, tmp_path):
    result = parse(api, scope, wire(source()) + b'\n' + wire(source('powershell4104')))
    entries = []
    for number, doc in enumerate(result.documents):
        name = f'synthetic-{number}.json'
        (tmp_path / name).write_bytes(doc.raw)
        entries.append({
            'path': name, 'source_ref': doc.source_ref, 'parser': doc.parser,
            'sha256': hashlib.sha256(doc.raw).hexdigest(),
            'context': {'ingested_at': scope.ingested_at, 'collection_mode': 'direct'},
        })
    (tmp_path / 'inputs.json').write_text(json.dumps({
        'bundle_schema_version': '0.1.0', 'environment_id': 'synthetic-env', 'files': entries,
    }), encoding='utf-8')
    for name in ('profile.json', 'context.json'):
        (tmp_path / name).write_bytes((FIXTURES / name).read_bytes())
    scenario = FIXTURES.parents[3] / 'scenarios/SCN-001-powershell-execution.yaml'
    cli = subprocess.run([
        sys.executable, '-m', 'aegis_verify', 'validate', '--scenario', str(scenario),
        '--fixture', str(tmp_path), '--format', 'json',
    ], capture_output=True, text=True, timeout=30)
    assert cli.returncode == 3, cli.stderr
    assert cli.stderr == ''
    report = json.loads(cli.stdout)
    assert report['evaluation']['final_status'] == 'Inconclusive'
    assert report['counts'] == {'parsed': 2, 'skipped': 0, 'referenced': 2}
    assert [a['outcome'] for a in report['evaluation']['assertions']] == [
        'satisfied', 'satisfied', 'inconclusive']
    assert report['evaluation']['assertions'][2]['reason_code'] == 'collection_not_confirmed'
    entries = report['evaluation']['evidence_index']
    assert {e['event_id'] for e in entries} == {d.telemetry.event.event_id for d in result.documents}
    for entry in entries:
        row = next(r for r in result.ledger if r.document_source_ref + '#record=1' == entry['raw_event_ref'])
        assert entry['raw_event_hash'] == row.document_sha256


def test_shared_archive_id_with_distinct_windows_events_is_kept(api, scope):
    # Wazuh writes archives.json in batches and gives one `id` to every record
    # flushed together, so distinct events share it. Measured on 4.14.4: a single
    # archive id covered 30 records with 30 different eventRecordID values.
    # Rejecting those would refuse real evidence, so identity comes from the
    # Windows event itself when the record carries one.
    a, b = source(), source()
    b['data']['win']['system']['eventRecordID'] = '102'
    b['data']['win']['eventdata']['processId'] = '4243'
    assert a['id'] == b['id']
    assert len(parse(api, scope, wire(a) + b'\n' + wire(b)).documents) == 2


def test_same_windows_event_delivered_twice_is_still_rejected(api, scope):
    # An agent can re-send an event it already delivered. That is a duplicate of
    # the same event, and it stays rejected even though the manager gave the two
    # copies different archive ids.
    a, b = source(), source()
    b['id'] = 'synthetic-sysmon-record-second-delivery'
    assert a['data']['win']['system']['eventRecordID'] == b['data']['win']['system']['eventRecordID']
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(a) + b'\n' + wire(b))
    assert caught.value.diagnostic.code == 'duplicate_record'


def test_same_event_record_id_on_another_channel_is_distinct(api, scope):
    # eventRecordID is only unique within one channel, so the channel and the
    # provider are part of the identity.
    a, b = source(), source('powershell4104')
    b['data']['win']['system']['eventRecordID'] = a['data']['win']['system']['eventRecordID']
    result = parse(api, scope, wire(a) + b'\n' + wire(b))
    assert len(result.documents) == 2


def test_records_without_a_windows_event_still_use_the_archive_id(api, scope):
    # Nothing else in the snapshot carries an event identity, so the previous
    # rule has to keep applying there. Both records are excluded before parsing,
    # which is where duplicate checks still have to run.
    a, b = source(), source()
    for record in (a, b):
        record['agent']['id'] = '999'
        record['data'] = {'synthetic': 'not-a-windows-event'}
    b['rule']['id'] = 'different-rule'
    with pytest.raises(api.ManagerSnapshotError) as caught:
        parse(api, scope, wire(a) + b'\n' + wire(b))
    assert caught.value.diagnostic.code == 'duplicate_record'
