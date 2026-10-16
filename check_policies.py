import re
from make_policies import policies

p = policies('Andhiki/slsa-gate-experiment')


def identity(policy):
    return policy['spec']['rules'][0]['verifyImages'][0]['attestations'][0]['attestors'][0]['entries'][0]['keyless']


main = 'https://github.com/Andhiki/slsa-gate-experiment/.github/workflows/build.yml@refs/heads/main'
alternate = main.replace('/main', '/experiment-disallowed-ref')
assert re.fullmatch(identity(p['P1'])['subjectRegExp'], main)
assert re.fullmatch(identity(p['P2'])['subjectRegExp'], main)
assert re.fullmatch(identity(p['P2'])['subjectRegExp'], alternate)
assert not re.fullmatch(identity(p['P2'])['subjectRegExp'], main.replace('slsa-gate-experiment/', 'slsa-gate-experiment-impostor/'))
assert not re.fullmatch(identity(p['P2'])['subjectRegExp'], main.replace('build.yml', 'other.yml'))
assert identity(p['P3']) == identity(p['P2'])
for policy in p.values():
    verification = policy['spec']['rules'][0]['verifyImages'][0]
    assert verification['imageReferences'] == ['*']
    assert verification['required'] and verification['verifyDigest']
    assert policy['spec']['failurePolicy'] == 'Fail'
    assert not identity(policy)['rekor'].get('ignoreTlog', False)
assert any(c['key'] == '{{ buildDefinition.externalParameters.workflow.ref }}' and c['value'] == 'refs/heads/main'
           for c in p['P3']['spec']['rules'][0]['verifyImages'][0]['attestations'][0]['conditions'][0]['all'])
print('Certificate regex regression and security invariants pass; live admission remains required.')
