"""Bounded keyed-attestation rotation scout. Outcomes are observations, not asserts."""
import copy
import hashlib
import json
import os
import pathlib
import time

import cache_trial as c
import metadata_proof as m

CM = '/api/v1/namespaces/slsa-experiment/configmaps/rotation-trust'
TYPE = 'https://slsa.dev/provenance/v1'


def policy(use_cache, nonce):
    p = copy.deepcopy(c.policies('Andhiki/slsa-gate-experiment')['P3'])
    p['metadata']['annotations']['rotation/nonce'] = nonce
    rule = p['spec']['rules'][0]
    rule['context'] = [{'name': 'trust', 'configMap': {
        'name': 'rotation-trust', 'namespace': 'slsa-experiment'}}]
    rule['verifyImages'] = [{
        'imageReferences': ['*'], 'type': 'Cosign', 'required': True,
        'mutateDigest': True, 'verifyDigest': True, 'useCache': use_cache,
        'attestations': [{'predicateType': TYPE, 'attestors': [{'entries': [{'keys': {
            'publicKeys': '{{ trust.data.publicKeys }}',
            'rekor': {'ignoreTlog': True}}}]}],
            'conditions': [{'all': [{'key': '{{ buildDefinition.buildType }}',
                'operator': 'Equals', 'value': 'https://example.invalid/rotation-fixture/v1'}]}]}]}]
    return p


def self_check():
    a, b = policy(False, 'a'), policy(True, 'b')
    assert a['spec']['rules'][0]['verifyImages'][0]['useCache'] is False
    assert b['spec']['rules'][0]['verifyImages'][0]['useCache'] is True
    assert b['spec']['rules'][0]['verifyImages'][0]['attestations'][0]['predicateType'] == TYPE
    assert b['spec']['rules'][0]['context'][0]['configMap']['name'] == 'rotation-trust'
    assert c.outcome_class(400, {'message': 'Service Unavailable'}) == 'infrastructure_error'
    assert c.outcome_class(201, {}) == 'accepted'
    return {'ok': True, 'policy_generation': True, 'classifier_controls': True}


def set_trust(text, phase):
    obj = {'apiVersion': 'v1', 'kind': 'ConfigMap',
           'metadata': {'name': 'rotation-trust', 'namespace': 'slsa-experiment'},
           'data': {'publicKeys': text}}
    code, existing, _ = c.api_json('GET', CM)
    if code == 200:
        obj['metadata']['resourceVersion'] = existing['metadata']['resourceVersion']
    start = c.utc_now()
    code, raw = c.kubectl_api('PUT' if code == 200 else 'POST',
                            CM if code == 200 else CM.rsplit('/', 1)[0], obj)
    result = {'phase': phase, 'started_at': start, 'completed_at': c.utc_now(),
              'http_status': code, 'object': c.parse_json(raw), 'raw': raw,
              'public_keys_sha256': hashlib.sha256(text.encode()).hexdigest()}
    c.append_jsonl(c.OUT / 'rotation-trust-updates.jsonl', result)
    if code not in (200, 201):
        raise RuntimeError('ConfigMap trust update failed: ' + raw)
    return result


def main():
    c.OUT.mkdir(exist_ok=True)
    self_check()
    run_id = os.environ.get('RUN_ID', 'trust-rotation')
    fixtures = json.loads((c.OUT / 'rotation-fixtures.json').read_text())
    old = pathlib.Path('/tmp/rotation-keys/old.pub').read_text()
    retained = pathlib.Path('/tmp/rotation-keys/retained.pub').read_text()
    assert old != retained
    cases = [{'case_id': key, 'oracle': 'fresh-deny' if key == 'old' else 'fresh-allow',
              'image': fixtures[key]} for key in ('old', 'retained')]
    result = {'run_id': run_id, 'protocol': 'TRUST_ROTATION_PROTOCOL.md',
              'ttl_seconds': 120, 'fixtures': fixtures, 'cells': [],
              'keyed_tlog_disabled': True, 'synthetic_not_slsa_builder_assurance': True}
    proxy = c.http_probe.start_proxy()
    try:
        result['controller_ttl'] = c.inspect_controller_cache_ttl(120)
        for mode in ('no-cache', 'native-cache', 'explicit-bump'):
            for network in ('normal', 'block'):
                cell = mode + '-' + network
                ctx = {'run_id': run_id, 'config': cell, 'seed': os.environ.get('SEED', 'scout')}
                c.record_control(run_id, cell, 'prepare', 'normal')
                initial = set_trust(old.strip() + '\n' + retained.strip() + '\n', cell + '-initial')
                c.apply_policy(policy(mode != 'no-cache', run_id + '-' + cell),
                               run_id, cell, 'prepare', wait_seconds=8)
                before = m.full_policy_snapshot('before-seed')
                controller_before = m.controller_snapshot('before-seed')
                seeds = [c.run_case(ctx, case, 'seed')[0] for case in cases]
                if any(row['http_status'] != 201 for row in seeds):
                    raise RuntimeError('setup: both keys must seed successfully: ' + cell)
                rotation = set_trust(retained, cell + '-rotate')
                c.record_control(run_id, cell, 'network', network)
                time.sleep(3)
                patch = None
                if mode == 'explicit-bump':
                    patch = m.json_patch_policy([{'op': 'replace',
                        'path': '/metadata/annotations/rotation~1nonce',
                        'value': run_id + '-' + cell + '-rotated'}])
                    if patch['http_status'] != 200:
                        raise RuntimeError('setup: explicit policy patch failed')
                time.sleep(3)
                after = m.full_policy_snapshot('after-rotation')
                probes = [c.run_case(ctx, case, 'post-rotation-probe')[0] for case in cases]
                c.record_control(run_id, cell, 'recovery', 'normal')
                recovery = [c.run_case(ctx, case, 'normal-registry-recovery')[0] for case in cases]
                entry = {'cell': cell, 'mode': mode, 'network': network,
                         'initial_trust': initial, 'rotation': rotation, 'patch': patch,
                         'policy_before': before, 'policy_after': after,
                         'controller_before': controller_before,
                         'controller_after': m.controller_snapshot('after-recovery'),
                         'seeds': seeds, 'probes': probes, 'recovery': recovery}
                result['cells'].append(entry)
                c.write_json(c.OUT / 'trust-rotation.json', result)
                print(json.dumps({'event': 'cell-complete', 'cell': cell,
                    'probes': [(r['case_id'], r['http_status'], r['outcome_class']) for r in probes]}), flush=True)
        result['completed_at'] = c.utc_now()
        c.write_json(c.OUT / 'trust-rotation.json', result)
    finally:
        c.write_json(c.OUT / 'trust-rotation.json', result)
        try:
            c.record_control(run_id, 'cleanup', 'normal', 'normal')
        finally:
            proxy.terminate()
            proxy.wait(timeout=5)


if __name__ == '__main__':
    main()
