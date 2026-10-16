import json
import pathlib
import tempfile
from cache_analyze import analyze

with tempfile.TemporaryDirectory() as folder:
    path = pathlib.Path(folder) / 'cache-requests.jsonl'
    row = {'run_id': 'unit-test', 'seed': 1, 'config': {'useCache': True},
           'phase': 'warm', 'case_id': 'main', 'outcome_class': 'accepted',
           'http_status': 201, 'latency_ms': 2, 'controller_pod_uid': 'one',
           'proxy_before': {'hosts': {'ghcr.io': {'connections': 2, 'blocked': 0}}},
           'proxy_after': {'hosts': {'ghcr.io': {'connections': 3, 'blocked': 1}}}}
    second = dict(row, latency_ms=4)
    path.write_text(json.dumps(row) + '\n' + json.dumps(second) + '\n', encoding='utf-8')
    result = analyze([path])
    assert result['n_requests'] == 2
    assert result['controller_identities'][0]['stable']
    group = result['groups'][0]
    assert group['median_ms'] == 3 and group['ghcr_connections_delta'] == 2
    assert group['outcomes'] == {'accepted': 2} and group['ghcr_blocked_delta'] == 2
    wrapped = dict(row, config='cache-enabled', cache={'useCache': True},
                   proxy_before={'sample': row['proxy_before']}, proxy_after={'sample': row['proxy_after']})
    path.write_text(json.dumps(wrapped) + '\n', encoding='utf-8')
    assert analyze([path])['groups'][0]['ghcr_connections_delta'] == 1
    wrapped['proxy_after'] = {'error': 'sample unavailable'}
    path.write_text(json.dumps(wrapped) + '\n', encoding='utf-8')
    assert analyze([path])['groups'][0]['ghcr_connections_delta'] is None
    try:
        analyze([path, path])
        raise AssertionError('Duplicate input should be rejected')
    except AssertionError as error:
        assert 'Duplicate source' in str(error)
print('Cache artifact aggregation self-check passed.')
