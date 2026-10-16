"""Public synthetic fixtures only: copy or tamper evidence without forging trust."""
import base64
import json
import os
import pathlib
import re
import subprocess

REPO = 'Andhiki/slsa-gate-experiment'
OUT = pathlib.Path('mutation-results')
OUT.mkdir(exist_ok=True)


def image(run):
    logs = subprocess.run(['gh', 'run', 'view', run, '-R', REPO, '--log'], text=True, capture_output=True, check=True).stdout
    digests = re.findall(r'DIGEST:\s+(sha256:[a-f0-9]{64})', logs)
    assert digests
    return 'ghcr.io/andhiki/slsa-gate-experiment@' + digests[-1]


source = image(os.environ['SOURCE_RUN'])
target = image(os.environ['TARGET_RUN'])
assert source != target
verified = subprocess.run(['gh', 'attestation', 'verify', 'oci://' + source, '-R', REPO,
                           '--bundle-from-oci', '--format', 'json'], text=True, capture_output=True, check=True)
bundle = json.loads(verified.stdout)[0]['attestation']['bundle']
original = json.loads(base64.b64decode(bundle['dsseEnvelope']['payload']))
kind = os.environ['MUTATION']
assert kind in ('substitution', 'tampered')
if kind == 'tampered':
    # Rebind the statement to the target without resigning: artifact binding now matches,
    # but signature/transparency evidence must fail on the modified statement.
    original['subject'][0]['digest']['sha256'] = target.split('@sha256:')[1]
    bundle['dsseEnvelope']['payload'] = base64.b64encode(json.dumps(original, separators=(',', ':')).encode()).decode()
(OUT / 'bundle.json').write_text(json.dumps(bundle))
attach = subprocess.run(['/tmp/oras', 'attach', '--artifact-type', 'application/vnd.dev.sigstore.bundle.v0.3+json',
                          target, str(OUT / 'bundle.json') + ':application/vnd.dev.sigstore.bundle.v0.3+json'],
                         text=True, capture_output=True)
(OUT / 'construction.json').write_text(json.dumps({'source': source, 'target': target, 'mutation': kind,
                                                   'attach_returncode': attach.returncode,
                                                   'stdout': attach.stdout, 'stderr': attach.stderr}, indent=2))
assert attach.returncode == 0, attach.stderr
check = subprocess.run(['gh', 'attestation', 'verify', 'oci://' + target, '-R', REPO,
                        '--bundle-from-oci', '--format', 'json'], text=True, capture_output=True)
(OUT / 'independent-negative-check.json').write_text(json.dumps({'returncode': check.returncode,
                                                               'stdout': check.stdout, 'stderr': check.stderr}, indent=2))
assert check.returncode != 0, 'Invalid fixture unexpectedly verified'
print(json.dumps({'mutation': kind, 'target': target, 'independent_verification_rejected': True}))
