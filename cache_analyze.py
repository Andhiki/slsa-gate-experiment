"""Describe explicitly selected cache session artifacts; never pool scout implicitly."""
import argparse
import collections
import json
import pathlib
import statistics


def counter(row, side, field):
    snapshot = row.get(side, {})
    if 'error' in snapshot:
        return None
    return snapshot.get('sample', snapshot).get('hosts', {}).get('ghcr.io', {}).get(field, 0)


def counter_delta(row, field):
    before, after = counter(row, 'proxy_before', field), counter(row, 'proxy_after', field)
    return after - before if before is not None and after is not None else None


def sum_deltas(rows, field):
    values = [counter_delta(row, field) for row in rows]
    return sum(values) if all(value is not None for value in values) else None


def analyze(paths):
    rows = []
    sources = []
    for path in paths:
        files = [path] if path.is_file() else sorted(path.rglob('cache-requests.jsonl'))
        for file in files:
            assert file not in sources, f'Duplicate source: {file}'
            sources.append(file)
            rows.extend(json.loads(line) for line in file.read_text(encoding='utf-8').splitlines() if line.strip())
    groups = collections.defaultdict(list)
    for row in rows:
        cache = row.get('cache', row['config'] if isinstance(row['config'], dict) else {})
        key = (row['run_id'], row['seed'], cache['useCache'], row['phase'], row['case_id'])
        groups[key].append(row)
    summary = []
    for (run, seed, cache, phase, case), values in groups.items():
        latencies = [v['latency_ms'] for v in values]
        summary.append({
            'run_id': run, 'seed': seed, 'useCache': cache, 'phase': phase, 'case_id': case,
            'n': len(values), 'outcomes': dict(collections.Counter(v['outcome_class'] for v in values)),
            'http_statuses': dict(collections.Counter(str(v['http_status']) for v in values)),
            'median_ms': statistics.median(latencies), 'min_ms': min(latencies), 'max_ms': max(latencies),
            'ghcr_connections_delta': sum_deltas(values, 'connections'),
            'ghcr_blocked_delta': sum_deltas(values, 'blocked'),
            'ghcr_bytes_in_delta': sum_deltas(values, 'bytes_in'),
            'ghcr_bytes_out_delta': sum_deltas(values, 'bytes_out'),
            'proxy_telemetry_errors': sum('error' in v.get(side, {}) for v in values for side in ('proxy_before', 'proxy_after')),
            'last_warm_success_to_probe_ms': [v.get('last_warm_success_to_probe_ms') for v in values],
        })
    sessions = {}
    for row in rows:
        sessions.setdefault((row['run_id'], row['seed']), set()).add(row['controller_pod_uid'])
    return {'files': [str(p) for p in sources], 'n_requests': len(rows),
            'controller_identities': [{'run_id': run, 'seed': seed, 'uids': sorted(uids, key=str),
                                       'stable': len(uids) == 1 and None not in uids} for (run, seed), uids in sessions.items()],
            'groups': summary,
            'scope': 'Descriptive fresh-cluster sessions; repeated requests are not independent applications.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='+', type=pathlib.Path)
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    result = analyze(args.paths)
    content = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(content + '\n', encoding='utf-8')
    else:
        print(content)
