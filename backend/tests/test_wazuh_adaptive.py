"""Adaptive collection must split only overflow, without gaps or partial success."""
import json
from copy import deepcopy
from pathlib import Path
import pytest
from aegis_verify.connectors.wazuh import live
from test_wazuh_live import config, page, Transport, HIT


def run(config_value, output, transport, **kwargs):
    assert hasattr(live, 'collect_adaptive'), 'adaptive collector is not implemented'
    return live.collect_adaptive(config_value, output, transport=transport, **kwargs)


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
