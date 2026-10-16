"""Hosted compatibility experiment; results are pilot-only, not confirmatory."""
import json
import os
import pathlib
import re
import subprocess
import time
from types import SimpleNamespace

import harness
from make_policies import policies
import http_probe

ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT / 'results'
OUT.mkdir(exist_ok=True)
REPO = 'Andhiki/slsa-gate-experiment'
KUBE = '/tmp/slsa-kubeconfig'
K = ['kubectl', '--kubeconfig', KUBE, '--context', 'kind-slsa-gate']


def command(argv, filename, check=True):
    p = subprocess.run(argv, text=True, capture_output=True, timeout=240)
    (OUT / filename).write_text(json.dumps({'argv': argv, 'returncode': p.returncode,
                                          'stdout': p.stdout, 'stderr': p.stderr}, indent=2))
    if check and p.returncode:
        raise RuntimeError(f'{filename} failed: {p.stderr[-1500:]}')
    return p


def fixture(run, name, oracle, branch):
    p = command(['gh', 'run', 'view', run, '-R', REPO, '--json', 'status,conclusion,headBranch,headSha,attempt,jobs'], name + '-run.json')
    data = json.loads(p.stdout)
    assert data['status'] == 'completed' and data['conclusion'] == 'success', (name, data['status'], data['conclusion'])
    assert data['headBranch'] == branch
    logs = subprocess.run(['gh', 'run', 'view', run, '-R', REPO, '--log'], capture_output=True, text=True, check=True).stdout
    matches = re.findall(r'DIGEST:\s+(sha256:[a-f0-9]{64})', logs)
    assert matches, f'No final image digest in {name} logs'
    return {'id': name, 'oracle': oracle, 'image': 'ghcr.io/andhiki/slsa-gate-experiment@' + matches[-1], 'run_id': run}


def trial(mode, policy_path=None):
    harness.run(SimpleNamespace(cases=str(OUT / 'cases.json'), kubeconfig=KUBE, mode=mode,
                               policy=str(policy_path) if policy_path else None, namespace='slsa-experiment',
                               run_id=mode, blocks=3, seed=20261016))


cases = [fixture(os.environ['MAIN_RUN'], 'legitimate-main', 'authorized', 'main'),
         fixture(os.environ['ALT_RUN'], 'authentic-disallowed-ref', 'unauthorized', 'experiment-disallowed-ref'),
         fixture(os.environ['UNSIGNED_RUN'], 'unsigned', 'unauthorized', 'main')]
assert len({c['image'] for c in cases}) == 3
(OUT / 'cases.json').write_text(json.dumps(cases, indent=2))

# Independent CLI verification against the registry, preserving full public evidence.
for case in cases:
    command(['gh', 'attestation', 'verify', 'oci://' + case['image'], '-R', REPO,
             '--bundle-from-oci', '--format', 'json'], case['id'] + '-crypto.json', check=False)
    if case['id'] != 'unsigned':
        command(['gh', 'attestation', 'verify', 'oci://' + case['image'], '-R', REPO,
                 '--bundle-from-oci', '--source-ref', 'refs/heads/main', '--format', 'json'],
                case['id'] + '-main-ref.json', check=False)

proxy = http_probe.start_proxy() if os.environ.get('PERFORMANCE') == 'true' else None

def measure(mode):
    if proxy:
        http_probe.benchmark(mode, cases[0]['image'])

trial('B0')
measure('B0')
command(['helm', 'repo', 'add', 'kyverno', 'https://kyverno.github.io/kyverno/'], 'helm-repo.json')
command(['helm', 'upgrade', '--install', 'kyverno', 'kyverno/kyverno', '--version', '3.9.1',
         '--namespace', 'kyverno', '--create-namespace', '--kubeconfig', KUBE,
         '--kube-context', 'kind-slsa-gate', '--values', 'kyverno-values.yaml', '--wait', '--timeout', '180s'],
        'helm-install.json')
trial('B1')
measure('B1')

for mode, policy in policies(REPO).items():
    path = OUT / (mode + '-policy.json')
    path.write_text(json.dumps(policy, indent=2))
    command(K + ['apply', '-f', str(path)], mode + '-apply.json')
    # Pilot propagation buffer, excluded from request timing; readiness saved for review.
    time.sleep(8)
    command(K + ['get', 'clusterpolicy', 'slsa-experiment', '-o', 'json'], mode + '-status.json')
    trial(mode, path)
    measure(mode)

rows = []
for file in OUT.glob('*/requests.jsonl'):
    rows.extend(json.loads(line) for line in file.read_text().splitlines())
summary = {}
for row in rows:
    summary.setdefault(row['policy'], {}).setdefault(row['case_id'], []).append(row['outcome'])
(OUT / 'summary.json').write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
for mode in ('P1', 'P2', 'P3'):
    assert all(x == 'allow' for x in summary[mode]['legitimate-main']), f'{mode}: legitimate fixture rejected'
    assert all(x == 'deny_needs_reason_review' for x in summary[mode]['unsigned']), f'{mode}: unsigned not rejected'
assert all(x == 'allow' for x in summary['P2']['authentic-disallowed-ref'])
assert all(x == 'deny_needs_reason_review' for x in summary['P3']['authentic-disallowed-ref'])
if proxy:
    proxy.terminate()
