"""Exploratory actual CREATE benchmark over local kubectl proxy, no process per request."""
import json
import pathlib
import statistics
import subprocess
import time
import urllib.error
import urllib.request
import uuid

K = ['kubectl', '--kubeconfig', '/tmp/slsa-kubeconfig', '--context', 'kind-slsa-gate']
ROOT = pathlib.Path(__file__).resolve().parent
BASE = 'http://127.0.0.1:18001'


def api(method, path, value=None):
    data = json.dumps(value).encode() if value is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=40) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def stats():
    code, body = api('GET', '/api/v1/nodes/slsa-gate-control-plane/proxy/stats/summary')
    if code != 200:
        return {'status': code, 'body': body}
    data = json.loads(body)
    return {'status': code, 'node_time': data.get('node', {}).get('startTime'),
            'pods': [p for p in data.get('pods', []) if p['podRef']['namespace'] == 'kyverno']}


def benchmark(mode, image, blocks=3, requests=20):
    target = ROOT / 'results' / ('http-' + mode)
    target.mkdir(exist_ok=False)
    all_rows = []
    for block in range(blocks):
        snapshots = [stats()]
        start = time.monotonic()
        for index in range(requests):
            name = 'http-' + uuid.uuid4().hex[:16]
            pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': 'slsa-experiment'},
                   'spec': {'nodeSelector': {'slsa-experiment.invalid/node': 'none'},
                            'automountServiceAccountToken': False,
                            'containers': [{'name': 'fixture', 'image': image}]}}
            before = time.perf_counter_ns()
            code, body = api('POST', '/api/v1/namespaces/slsa-experiment/pods', pod)
            row = {'mode': mode, 'block': block, 'index': index, 'status': code,
                   'api_roundtrip_ms': (time.perf_counter_ns() - before) / 1e6,
                   'body': body if code != 201 else ''}
            all_rows.append(row)
            if code == 201:
                api('DELETE', '/api/v1/namespaces/slsa-experiment/pods/' + name,
                    {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'gracePeriodSeconds': 0})
            # Snapshot overhead is outside timed POST, inside block resource measurement.
            if index % 5 == 4:
                snapshots.append(stats())
        snapshots.append(stats())
        (target / f'block-{block}-stats.json').write_text(json.dumps({'wall_seconds': time.monotonic() - start,
                                                                    'snapshots': snapshots}, indent=2))
    (target / 'requests.jsonl').write_text(''.join(json.dumps(x) + '\n' for x in all_rows))
    accepted = [r['api_roundtrip_ms'] for r in all_rows if r['status'] == 201]
    summary = {'mode': mode, 'requests': len(all_rows), 'accepted': len(accepted),
               'median_api_roundtrip_ms': statistics.median(accepted) if accepted else None,
               'min_ms': min(accepted) if accepted else None, 'max_ms': max(accepted) if accepted else None,
               'scope': 'pilot sequential CREATE, repeated authorized digest; includes proxy/API, not pure webhook time',
               'resource_scope': 'whole controller per block including GET stats and DELETE cleanup; not verification-only CPU'}
    (target / 'summary.json').write_text(json.dumps(summary, indent=2))
    assert len(accepted) == len(all_rows), f'{mode}: authorized performance fixture rejected'


def start_proxy():
    log = (ROOT / 'results/proxy.log').open('w')
    proc = subprocess.Popen(K + ['proxy', '--port=18001', '--address=127.0.0.1'], stdout=log, stderr=log)
    for _ in range(40):
        try:
            if api('GET', '/version')[0] == 200:
                return proc
        except OSError:
            pass
        time.sleep(0.25)
    proc.terminate()
    raise RuntimeError('kubectl proxy not ready')
