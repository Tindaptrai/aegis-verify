"""Adaptive collection must split only overflow, without gaps or partial success."""
import json
import hashlib
import io
import os
from copy import deepcopy
from pathlib import Path
from urllib.error import URLError
import pytest
from aegis_verify.connectors.wazuh import live
from test_wazuh_live import config, page, Transport, HIT
from aegis_verify import private_fs
from windows_acl import assert_owner_only


def run(config_value, output, transport, **kwargs):
    assert hasattr(live, 'collect_adaptive'), 'adaptive collector is not implemented'
    return live.collect_adaptive(config_value, output, transport=transport, **kwargs)


@pytest.mark.skipif(os.name != 'nt', reason='Windows ACL integration')
def test_windows_adaptive_output_and_leaf_have_owner_only_acl(tmp_path):
    out = tmp_path / 'batch'
    run(config(), out, Transport([page([], total=0)]))
    assert_owner_only(out)
    assert_owner_only(out / 'attempt-0001')


def test_adaptive_leaf_directory_failure_stops_before_source_request(tmp_path, monkeypatch):
    create = private_fs._create
    def fail_leaf(target):
        if target.name == 'attempt-0001':
            raise OSError('injected')
        create(target)
    monkeypatch.setattr(private_fs, '_create', fail_leaf)
    transport = Transport([page([], total=0)])
    out = tmp_path / 'batch'
    with pytest.raises(live.LiveError, match='^output_error$'):
        run(config(), out, transport)
    assert transport.calls == []
    assert (out / 'INCOMPLETE').exists()
    assert not (out / 'attempt-0001').exists()
    assert not (out / 'batch.json').exists()


def test_overflow_has_distinct_error(tmp_path):
    with pytest.raises(live.LiveError, match='^record_limit$'):
        live.collect(config(), tmp_path/'one', transport=Transport([page([], total=101)]))


def test_split_preserves_precise_half_open_boundaries_and_failed_evidence(tmp_path):
    t = Transport([page([], total=101), page([], total=0), page([], total=0)])
    out = tmp_path/'batch'
    result = run(config(start='2026-01-01T00:00:00.0000001Z',
                        end='2026-01-01T00:00:04.0000001Z'), out, t)
    windows = [body['query']['bool']['filter'][1]['range']['timestamp']
               for method, path, body in t.calls if path.endswith('scroll=1m')]
    assert windows[1:] == [
        {'gte':'2026-01-01T00:00:00.0000001Z', 'lt':'2026-01-01T00:00:02.000000100Z'},
        {'gte':'2026-01-01T00:00:02.000000100Z', 'lt':'2026-01-01T00:00:04.0000001Z'}]
    assert result['query_complete'] is True
    assert result['record_count'] == 0
    assert len(result['collections']) == 2
    assert (out/'attempt-0001'/'INCOMPLETE').exists()
    assert not (out/'INCOMPLETE').exists()
    assert json.loads((out/'batch.json').read_bytes()) == result


@pytest.mark.parametrize('error', ['authentication_failed','permission_denied',
                                  'count_limit_or_mismatch','connection_or_tls_failed'])
def test_non_overflow_error_never_splits_or_publishes(tmp_path, error):
    t = Transport([live.LiveError(error)])
    with pytest.raises(live.LiveError, match=error):
        run(config(), tmp_path/'batch', t)
    assert len(t.calls) == 1
    assert (tmp_path/'batch'/'INCOMPLETE').exists()
    assert not (tmp_path/'batch'/'batch.json').exists()


def test_dense_minimum_window_stops(tmp_path):
    with pytest.raises(live.LiveError, match='split_limit'):
        run(config(start='2026-01-01T00:00:00Z',end='2026-01-01T00:00:01Z'),
            tmp_path/'batch',Transport([page([],total=101)]))


def test_attempt_budget_stops_without_success_manifest(tmp_path):
    with pytest.raises(live.LiveError, match='batch_attempt_limit'):
        run(config(),tmp_path/'batch',Transport([page([],total=101)]), max_attempts=1)
    assert not (tmp_path/'batch'/'batch.json').exists()


def test_existing_output_never_overwritten(tmp_path):
    out=tmp_path/'batch'; out.mkdir(); (out/'keep').write_text('keep')
    with pytest.raises(live.LiveError,match='output_exists'):
        run(config(),out,Transport([]))
    assert (out/'keep').read_text()=='keep'


def test_cleanup_failure_aggregated(tmp_path):
    class CleanupFailure(Transport):
        def request(self, method, path, body):
            if method == 'DELETE':
                raise live.LiveError('permission_denied')
            return super().request(method,path,body)
    result=run(config(),tmp_path/'batch',CleanupFailure([page([],total=0)]))
    assert result['cleanup_failed'] is True
    assert result['collection_assurance']=='unknown'


def test_nonempty_collection_keeps_canonical_output(tmp_path):
    result=run(config(),tmp_path/'batch',Transport([page([HIT]),page([])]))
    assert result['record_count']==1
    leaf=tmp_path/'batch'/result['collections'][0]['path']
    assert len(json.loads((leaf/'canonical.json').read_bytes()))==1
    assert (leaf/'inputs.json').exists()


def test_failed_overflow_cleanup_must_not_be_hidden_by_split(tmp_path):
    class CleanupFailure(Transport):
        def request(self, method, path, body):
            if method=='DELETE':
                raise live.LiveError('permission_denied')
            return super().request(method,path,body)
    with pytest.raises(live.LiveError,match='cleanup_failed'):
        run(config(),tmp_path/'batch',CleanupFailure([page([],total=101)]))
    assert not (tmp_path/'batch'/'batch.json').exists()


def test_changed_total_is_not_treated_as_overflow(tmp_path):
    with pytest.raises(live.LiveError,match='count_limit_or_mismatch'):
        run(config(),tmp_path/'batch',Transport([page([HIT]),page([],total=101)]))
    assert len(list((tmp_path/'batch').glob('attempt-*')))==1


def test_batch_deadline_stops_before_new_request(tmp_path,monkeypatch):
    times=iter([0,601])
    monkeypatch.setattr(live.time,'monotonic',lambda:next(times))
    with pytest.raises(live.LiveError,match='batch_deadline'):
        run(config(),tmp_path/'batch',Transport([]))


def test_cli_adaptive_uses_real_batch_collector(tmp_path,monkeypatch,capsys):
    monkeypatch.setenv('WAZUH_INDEXER_URL','https://indexer.example.test')
    monkeypatch.setenv('WAZUH_INDEXER_USERNAME','test-reader')
    monkeypatch.setenv('WAZUH_INDEXER_PASSWORD','test-only-secret')
    monkeypatch.setattr(live,'HttpsTransport',lambda cfg:Transport([page([],total=0)]))
    code=live.main(['--adaptive','--index','wazuh-alerts-*','--agent','901',
        '--start','2026-01-01T00:00:00Z','--end','2026-01-01T00:00:02Z',
        '--environment','test','--output',str(tmp_path/'batch')])
    assert code==0
    assert json.loads(capsys.readouterr().out)['query_complete'] is True
    assert (tmp_path/'batch'/'batch.json').exists()


def test_manifest_read_error_has_fixed_diagnostic(tmp_path, monkeypatch):
    original = Path.read_bytes
    def read(path):
        if path.name == 'collection.json':
            raise OSError('private filesystem detail')
        return original(path)
    monkeypatch.setattr(Path, 'read_bytes', read)
    with pytest.raises(live.LiveError, match='^output_error$'):
        run(config(), tmp_path/'batch', Transport([page([], total=0)]))
    assert (tmp_path/'batch'/'INCOMPLETE').exists()
    assert not (tmp_path/'batch'/'batch.json').exists()


def test_nonempty_split_assigns_midpoint_to_right_leaf(tmp_path):
    left, right = deepcopy(HIT), deepcopy(HIT)
    left['_id'], right['_id'] = 'left', 'right'
    left['_source']['timestamp'] = '2026-01-01T00:00:01Z'
    right['_source']['timestamp'] = '2026-01-01T00:00:02Z'
    t = Transport([page([], total=101), page([left]), page([]), page([right]), page([])])
    out = tmp_path/'batch'
    result = run(config(start='2026-01-01T00:00:00Z', end='2026-01-01T00:00:04Z'), out, t)
    assert result['record_count'] == 2
    assert [x['record_count'] for x in result['collections']] == [1, 1]
    for leaf, expected in zip(result['collections'], ['left', 'right']):
        hit = json.loads((out/leaf['path']/'hit-000001.json').read_bytes())
        assert hit['_id'] == expected
        assert (out/leaf['path']/'inputs.json').exists()


def test_failed_right_leaf_retains_completed_left_evidence(tmp_path):
    left = deepcopy(HIT)
    left['_source']['timestamp'] = '2026-01-01T00:00:01Z'
    out = tmp_path/'batch'
    with pytest.raises(live.LiveError, match='permission_denied'):
        run(config(start='2026-01-01T00:00:00Z', end='2026-01-01T00:00:04Z'), out,
            Transport([page([], total=101), page([left]), page([]), live.LiveError('permission_denied')]))
    assert json.loads((out/'attempt-0002'/'hit-000001.json').read_bytes()) == left
    assert (out/'attempt-0002'/'inputs.json').exists()
    assert not (out/'attempt-0002'/'INCOMPLETE').exists()
    assert (out/'INCOMPLETE').exists()
    assert not (out/'batch.json').exists()


def synthetic_hit(identity, timestamp):
    hit = deepcopy(HIT)
    hit['_id'] = identity
    hit['_source']['timestamp'] = timestamp
    return hit


def test_single_collection_prefix_is_applied_before_canonical_parsing(tmp_path):
    out = tmp_path / 'one'
    live.collect(config(), out, transport=Transport([page([HIT]), page([])]),
                 source_ref_prefix='attempt-0002-')
    entry = json.loads((out / 'inputs.json').read_bytes())['files'][0]
    event = json.loads((out / 'canonical.json').read_bytes())[0]
    assert entry['path'] == 'hit-000001.json'
    assert entry['source_ref'] == 'attempt-0002-hit-000001'
    assert event['raw_event_ref'] == 'attempt-0002-hit-000001#record=1'
    expected = live.parse_wazuh_document((out / entry['path']).read_bytes(),
        source_ref='attempt-0002-hit-000001', environment_id='test',
        **entry['context']).event.model_dump(mode='json')
    assert event == expected


def test_namespaced_siblings_have_distinct_canonical_refs_and_manifest_hashes(tmp_path):
    left = synthetic_hit('left', '2026-01-01T00:00:01Z')
    right = synthetic_hit('right', '2026-01-01T00:00:03Z')
    out = tmp_path / 'batch'
    result = run(config(start='2026-01-01T00:00:00Z', end='2026-01-01T00:00:04Z'),
        out, Transport([page([left], total=174), page([left]), page([]),
                        page([right]), page([])]), namespace_sources=True)
    assert result['environment_id'] == 'test'
    events = []
    for member, expected_ref in zip(result['collections'],
            ['attempt-0002-hit-000001', 'attempt-0003-hit-000001']):
        leaf = out / member['path']
        raw_inputs = (leaf / 'inputs.json').read_bytes()
        assert member['inputs_sha256'] == hashlib.sha256(raw_inputs).hexdigest()
        collection = json.loads((leaf / 'collection.json').read_bytes())
        assert collection['environment_id'] == 'test'
        entry = json.loads(raw_inputs)['files'][0]
        event = json.loads((leaf / 'canonical.json').read_bytes())[0]
        assert entry['source_ref'] == expected_ref
        assert event['raw_event_ref'] == expected_ref + '#record=1'
        expected = live.parse_wazuh_document((leaf / entry['path']).read_bytes(),
            source_ref=expected_ref, environment_id='test',
            **entry['context']).event.model_dump(mode='json')
        assert event == expected
        events.append(event)
    assert events[0]['event_id'] != events[1]['event_id']
    assert (out / 'attempt-0001' / 'INCOMPLETE').exists()


def test_empty_leaf_records_environment_and_null_inputs_hash(tmp_path):
    result = run(config(), tmp_path / 'batch', Transport([page([], total=0)]))
    assert result['environment_id'] == 'test'
    assert result['collections'][0]['inputs_sha256'] is None
    summary = json.loads((tmp_path / 'batch/attempt-0001/collection.json').read_bytes())
    assert summary['environment_id'] == 'test'


def test_duplicate_native_identity_across_successful_siblings_fails_closed(tmp_path):
    left = synthetic_hit('same-native-id', '2026-01-01T00:00:01Z')
    right = synthetic_hit('same-native-id', '2026-01-01T00:00:03Z')
    out = tmp_path / 'batch'
    transport = Transport([page([], total=101), page([left]), page([]),
                           page([right]), page([])])
    with pytest.raises(live.LiveError, match='^duplicate_record$'):
        run(config(start='2026-01-01T00:00:00Z', end='2026-01-01T00:00:04Z'),
            out, transport)
    assert (out / 'INCOMPLETE').exists()
    assert (out / 'attempt-0001/INCOMPLETE').exists()
    assert (out / 'attempt-0003/INCOMPLETE').exists()
    assert (out / 'attempt-0002/inputs.json').exists()
    assert not (out / 'batch.json').exists()
    assert transport.calls[-1][0] == 'DELETE'


def test_shared_byte_budget_includes_failed_parent_responses(tmp_path):
    # Without the overflow parent these 64 responses plus cleanup fit 16 MiB.
    # Every response independently fits the 256 KiB response decoder limit.
    def padded(hits, total):
        return page(hits, total=total).ljust(256 * 1024 - 1, b' ')
    left = [synthetic_hit(f'left-{i}', '2026-01-01T00:00:01Z') for i in range(31)]
    right = [synthetic_hit(f'right-{i}', '2026-01-01T00:00:03Z') for i in range(31)]
    responses = [padded([], 101)]
    for hits in (left, right):
        responses.extend(padded([hit], 31) for hit in hits)
        responses.append(padded([], 31))
    out = tmp_path / 'batch'
    transport = Transport(responses)
    with pytest.raises(live.LiveError, match='^batch_byte_limit$'):
        run(config(start='2026-01-01T00:00:00Z', end='2026-01-01T00:00:04Z',
                   page_size=1), out, transport)
    assert (out / 'INCOMPLETE').exists()
    assert (out / 'attempt-0001/INCOMPLETE').exists()
    assert not (out / 'batch.json').exists()
    assert transport.calls[-1][0] == 'DELETE'
    assert sum(path.stat().st_size for path in out.glob('attempt-*/response-*.json')) <= 16 * 1024 * 1024


def test_shared_deadline_includes_failed_parents_and_stops_during_leaf(tmp_path, monkeypatch):
    elapsed = [0]
    class SlowTransport(Transport):
        def request(self, method, path, body):
            result = super().request(method, path, body)
            if path.endswith('scroll=1m'):
                elapsed[0] += 201
            return result
    monkeypatch.setattr(live.time, 'monotonic', lambda: elapsed[0])
    transport = SlowTransport([page([], total=101), page([], total=0), page([], total=0)])
    out = tmp_path / 'batch'
    with pytest.raises(live.LiveError, match='^batch_deadline$'):
        run(config(start='2026-01-01T00:00:00Z', end='2026-01-01T00:00:04Z'),
            out, transport)
    assert elapsed[0] == 603
    assert transport.calls[-1][0] == 'DELETE'
    assert (out / 'INCOMPLETE').exists()
    assert not (out / 'batch.json').exists()


def test_synthetic_174_records_are_retained_in_namespaced_bounded_leaves(tmp_path):
    left = [synthetic_hit(f'synthetic-{i:03d}', '2026-01-01T00:00:01Z') for i in range(87)]
    right = [synthetic_hit(f'synthetic-{i:03d}', '2026-01-01T00:00:03Z') for i in range(87, 174)]
    responses = [page([], total=174)]
    for hits in (left, right):
        responses.extend(page(hits[i:i + 20], total=87) for i in range(0, 87, 20))
        responses.append(page([], total=87))
    out = tmp_path / 'batch'
    result = run(config(start='2026-01-01T00:00:00Z', end='2026-01-01T00:00:04Z'),
        out, Transport(responses), namespace_sources=True)
    assert result['record_count'] == 174
    assert result['attempts'] == 3
    assert [member['record_count'] for member in result['collections']] == [87, 87]
    events, native_ids, refs = [], [], []
    for member in result['collections']:
        leaf = out / member['path']
        inputs = json.loads((leaf / 'inputs.json').read_bytes())['files']
        events.extend(json.loads((leaf / 'canonical.json').read_bytes()))
        refs.extend(entry['source_ref'] for entry in inputs)
        native_ids.extend(json.loads((leaf / entry['path']).read_bytes())['_id'] for entry in inputs)
    assert len(events) == len({event['event_id'] for event in events}) == 174
    assert len(refs) == len(set(refs)) == 174
    assert set(native_ids) == {f'synthetic-{i:03d}' for i in range(174)}
    assert result['collection_assurance'] == 'unknown'
    assert result['snapshot_scope'] == 'per-collection'
    assert (out / 'attempt-0001/INCOMPLETE').exists()


def test_shared_deadline_is_checked_before_final_batch_publication(tmp_path, monkeypatch):
    elapsed = [0]
    original = Path.read_bytes
    def read(path):
        result = original(path)
        if path.name == 'collection.json':
            elapsed[0] = 601
        return result
    monkeypatch.setattr(live.time, 'monotonic', lambda: elapsed[0])
    monkeypatch.setattr(Path, 'read_bytes', read)
    out = tmp_path / 'batch'
    with pytest.raises(live.LiveError, match='^batch_deadline$'):
        run(config(), out, Transport([page([], total=0)]))
    assert (out / 'INCOMPLETE').exists()
    assert not (out / 'batch.json').exists()


def test_maximum_binary_collection_set_has_63_attempts_and_32_leaves(tmp_path):
    def tree(depth):
        if depth == 5:
            return [page([], total=0)]
        return [page([], total=101), *tree(depth + 1), *tree(depth + 1)]
    out = tmp_path / 'batch'
    result = run(config(start='2026-01-01T00:00:00Z', end='2026-01-01T00:01:04Z'),
                 out, Transport(tree(0)))
    assert result['attempts'] == 63
    assert len(result['collections']) == 32
    assert len(list(out.glob('attempt-*/INCOMPLETE'))) == 31


def test_expired_batch_gives_cleanup_one_bounded_request_and_never_splits(tmp_path, monkeypatch):
    elapsed, methods, timeouts = [0], [], []
    transport = live.HttpsTransport(config())
    class SlowCleanup(io.BytesIO):
        def read(self, size=-1):
            elapsed[0] += 31
            return super().read(size)
        def read1(self, size=-1):
            elapsed[0] += 31
            return super().read1(size)
    def respond(request, *, timeout):
        methods.append(request.get_method())
        timeouts.append(timeout)
        if methods == ['POST']:
            return io.BytesIO(page([HIT]))
        if request.get_method() == 'POST':
            elapsed[0] = 601
            raise URLError('injected')
        return SlowCleanup(b'{"succeeded":true}')
    monkeypatch.setattr(live.time, 'monotonic', lambda: elapsed[0])
    monkeypatch.setattr(transport._opener, 'open', respond)
    out = tmp_path / 'batch'
    with pytest.raises(live.LiveError, match='^cleanup_failed$'):
        run(config(), out, transport)
    assert methods == ['POST', 'POST', 'DELETE']
    assert elapsed[0] == 632
    assert timeouts[-1] <= 30
    assert (out / 'INCOMPLETE').exists()
    assert not (out / 'batch.json').exists()


def test_real_transport_stops_at_per_collection_deadline_before_accepting_response(tmp_path, monkeypatch):
    elapsed, methods = [0], []
    responses = iter(page([synthetic_hit(f'hit-{i}', HIT['_source']['timestamp'])], total=17)
                     for i in range(17))
    transport = live.HttpsTransport(config())
    def respond(request, *, timeout):
        methods.append(request.get_method())
        if request.get_method() == 'DELETE':
            return io.BytesIO(b'{"succeeded":true}')
        elapsed[0] += 20
        return io.BytesIO(next(responses))
    monkeypatch.setattr(live.time, 'monotonic', lambda: elapsed[0])
    monkeypatch.setattr(transport._opener, 'open', respond)
    out = tmp_path / 'one'
    with pytest.raises(live.LiveError, match='^collection_deadline$'):
        live.collect(config(page_size=1), out, transport=transport)
    assert elapsed[0] == 300
    assert methods == ['POST'] * 15 + ['DELETE']
    assert len(list(out.glob('response-*.json'))) == 14
    assert (out / 'INCOMPLETE').exists()


def test_real_transport_stops_at_shared_deadline_before_accepting_response(tmp_path, monkeypatch):
    elapsed, methods = [0], []
    responses = [page([], total=174)]
    responses.extend(page([synthetic_hit(f'left-{i}', '2026-01-01T00:00:01Z')], total=13)
                     for i in range(13))
    responses.append(page([], total=13))
    responses.extend(page([synthetic_hit(f'right-{i}', '2026-01-01T00:00:03Z')], total=17)
                     for i in range(17))
    responses = iter(responses)
    transport = live.HttpsTransport(config())
    def respond(request, *, timeout):
        methods.append(request.get_method())
        if request.get_method() == 'DELETE':
            return io.BytesIO(b'{"succeeded":true}')
        elapsed[0] += 20
        return io.BytesIO(next(responses))
    monkeypatch.setattr(live.time, 'monotonic', lambda: elapsed[0])
    monkeypatch.setattr(transport._opener, 'open', respond)
    out = tmp_path / 'batch'
    with pytest.raises(live.LiveError, match='^batch_deadline$'):
        run(config(start='2026-01-01T00:00:00Z', end='2026-01-01T00:00:04Z', page_size=1),
            out, transport)
    assert elapsed[0] == 600
    assert methods.count('POST') == 30
    assert methods.count('DELETE') == 3
    assert len(list((out / 'attempt-0003').glob('response-*.json'))) == 14
    assert (out / 'attempt-0002/inputs.json').exists()
    assert (out / 'INCOMPLETE').exists()
    assert not (out / 'batch.json').exists()
