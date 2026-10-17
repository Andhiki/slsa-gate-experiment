"""Bounded npm integration scout. Standard library only; runs on hosted Linux."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

CASES = {
    'lodash': ('4.17.20', '4.17.21', "const a=require('node:assert/strict'),m=require('lodash');a.deepEqual(m.chunk([1,2,3],2),[[1,2],[3]]);"),
    'esbuild': ('0.25.9', '0.25.10', "const a=require('node:assert/strict'),m=require('esbuild');const r=m.transformSync('const n:number=21;globalThis.answer=n*2',{loader:'ts'});require('node:vm').runInThisContext(r.code);a.equal(globalThis.answer,42);"),
    'sharp': ('0.34.3', '0.34.4', "const a=require('node:assert/strict'),m=require('sharp');(async()=>{const b=await m({create:{width:3,height:2,channels:3,background:'#ff0000'}}).png().toBuffer();const d=await m(b).metadata();a.equal(d.width,3);a.equal(d.height,2);a.equal(d.format,'png')})().catch(e=>{console.error(e);process.exit(1)});"),
    'bcrypt': ('5.1.1', '6.0.0', "const a=require('node:assert/strict'),m=require('bcrypt');const h=m.hashSync('pilot-value',4);a.equal(m.compareSync('pilot-value',h),true);a.equal(m.compareSync('wrong',h),false);"),
    'canvas': ('3.1.2', '3.2.0', "const a=require('node:assert/strict'),m=require('canvas');const c=m.createCanvas(3,2),x=c.getContext('2d');x.fillStyle='#ff0000';x.fillRect(0,0,3,2);a.deepEqual(Array.from(x.getImageData(0,0,1,1).data),[255,0,0,255]);a.equal(c.toBuffer('image/png').subarray(1,4).toString(),'PNG');"),
}
ARMS = ('all', 'none', 'name', 'pinned', 'refreshed')
ROOT = Path('results/npm')
NPM = os.environ.get('PILOT_NPM', '/tmp/npm-pilot-cli/node_modules/npm/bin/npm-cli.js')

def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding='utf-8')

def run(args, cwd, label):
    start = time.monotonic()
    # No inherited GitHub token or unrelated npm policy configuration.
    env = {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in ('TOKEN', 'SECRET', 'PASSWORD', 'NPM_CONFIG_'))}
    env.update({'CI':'true', 'NPM_CONFIG_CACHE':'/tmp/npm-pilot-cache', 'NPM_CONFIG_USERCONFIG':'/dev/null', 'NPM_CONFIG_GLOBALCONFIG':'/tmp/npm-pilot-empty-global.npmrc'})
    try:
        p = subprocess.run(args, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        code, output = p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        code, output = 124, str(e.stdout or '') + '\nTIMEOUT'
    (cwd / (label + '.log')).write_text(output, encoding='utf-8')
    return {'exit':code, 'seconds':round(time.monotonic()-start, 4)}

def npm(args, cwd, label):
    return run(['node', NPM, *args, '--no-audit', '--no-fund'], cwd, label)

def hooks(lock):
    found = {}
    for loc, entry in lock['packages'].items():
        if loc and entry.get('hasInstallScript'):
            name = entry.get('name') or loc.rsplit('node_modules/', 1)[-1]
            found[name + '@' + entry['version']] = name
    return found

def approval(arm, initial, current):
    if arm == 'name':
        return dict.fromkeys(initial.values(), True)
    if arm == 'pinned':
        return dict.fromkeys(initial, True)
    if arm == 'refreshed':
        return dict.fromkeys(current, True)
    return {}

def sentinel():
    base = ROOT / 'sentinel'
    base.mkdir(parents=True, exist_ok=True)
    packages = []
    for version in ('1.0.0', '1.0.1'):
        path = (base / (version + '.tgz')).resolve()
        files = {'package.json': json.dumps({'name':'pilot-sentinel','version':version,'main':'index.js','scripts':{'install':'node install.js'}}),
                 'install.js': "require('fs').writeFileSync('INSTALL_MARKER','safe')",
                 'index.js': "require('fs').writeFileSync(require('path').join(__dirname,'IMPORT_MARKER'),'safe');module.exports=42;"}
        with tarfile.open(path, 'w:gz') as tar:
            for name, data in files.items():
                blob = data.encode(); info = tarfile.TarInfo('package/' + name); info.size = len(blob)
                tar.addfile(info, io.BytesIO(blob))
        packages.append(path)
    rows = []
    for i, path in enumerate(packages):
        for arm in ARMS:
            work = base / (str(i) + '-' + arm); work.mkdir()
            policy = {'name':{'pilot-sentinel':True},'pinned':{'pilot-sentinel@1.0.0':True},'refreshed':{'pilot-sentinel@' + ('1.0.0' if i == 0 else '1.0.1'):True}}.get(arm,{})
            save(work/'package.json', {'name':'sentinel-host','version':'1.0.0','private':True,'dependencies':{'pilot-sentinel':'file:' + str(path)},'allowScripts':policy})
            flags = ['--dangerously-allow-all-scripts'] if arm == 'all' else ['--ignore-scripts'] if arm == 'none' else []
            install = npm(['install', *flags], work, 'install')
            marker = work/'node_modules/pilot-sentinel/INSTALL_MARKER'
            imported = npm_import = run(['node','-e', "require('node:assert/strict').equal(require('pilot-sentinel'),42)"], work, 'functional')
            expected = arm in ('all','name','refreshed') or (arm == 'pinned' and i == 0)
            row = {'version':i,'arm':arm,'install':install,'functional':imported,'marker':marker.exists(),'expected':expected,'import_marker':(marker.parent/'IMPORT_MARKER').exists()}
            rows.append(row); save(base/'controls.json', rows)
            assert install['exit'] == 0 and npm_import['exit'] == 0 and marker.exists() == expected and row['import_marker'], row
    return rows

def trial(case):
    versions = CASES[case][:2]
    root = ROOT / case; root.mkdir(parents=True, exist_ok=True)
    summary = {'case':case,'versions':versions,'rows':[], 'scope':'package integration only; no real-project CI outcome'}
    save(root/'environment.json', {'node':subprocess.check_output(['node','--version'],text=True).strip(),'npm':subprocess.check_output(['node',NPM,'--version'],text=True).strip(),'platform':sys.platform,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    initial = None
    for index, version in enumerate(versions):
        snapshot = root / version; snapshot.mkdir()
        manifest = {'name':'integration-pilot','version':'1.0.0','private':True,'dependencies':{case:version}}
        save(snapshot/'package.json',manifest)
        locked = npm(['install','--package-lock-only','--ignore-scripts'], snapshot, 'resolve')
        if locked['exit'] != 0:
            summary['setup_error'] = {'version':version,'resolve':locked}; break
        locktext = (snapshot/'package-lock.json').read_text()
        current = hooks(json.loads(locktext))
        if initial is None: initial = current.copy()
        for arm in ARMS:
            work = snapshot / arm; work.mkdir()
            manifest_arm = dict(manifest, allowScripts=approval(arm, initial, current))
            save(work/'package.json', manifest_arm)
            (work/'package-lock.json').write_text(locktext)
            flags = ['--dangerously-allow-all-scripts'] if arm == 'all' else ['--ignore-scripts'] if arm == 'none' else []
            install = npm(['ci', *flags], work, 'install')
            check = run(['node','-e',CASES[case][2]], work, 'functional') if install['exit'] == 0 else None
            actual = hashlib.sha256((work/'package-lock.json').read_bytes()).hexdigest()
            expected = hashlib.sha256(locktext.encode()).hexdigest()
            assert actual == expected, 'lock changed across arms'
            row = {'version':version,'index':index,'arm':arm,'install':install,'functional':check,'lock_sha256':actual,'current_script_entries':list(current),'approval':manifest_arm['allowScripts'],'new_version_entries':sorted(set(current)-set(initial)), 'outcome':'install_failure' if install['exit'] else 'functional_pass' if check['exit'] == 0 else 'install_success_functional_failure'}
            summary['rows'].append(row); save(root/'summary.json',summary)
            print(json.dumps({'case':case,**row}),flush=True)
    save(root/'summary.json',summary)
    assert len(summary['rows']) == 10 and all(r['outcome']=='functional_pass' for r in summary['rows'] if r['arm']=='all'), 'allow-all reference or setup failed; inspect evidence'

def selfcheck():
    h=hooks({'packages':{'':{},'node_modules/@a/b':{'version':'1.2.3','hasInstallScript':True},'node_modules/x':{'version':'2','hasInstallScript':False}}})
    assert h == {'@a/b@1.2.3':'@a/b'}
    assert approval('name',h,{}) == {'@a/b':True}
    assert approval('pinned',h,{}) == {'@a/b@1.2.3':True}
    assert approval('refreshed',h,{}) == {}

if __name__ == '__main__':
    selfcheck()
    if sys.argv[1] == 'selfcheck': print('selfcheck passed')
    elif sys.argv[1] == 'sentinel': sentinel()
    else: trial(sys.argv[1])
