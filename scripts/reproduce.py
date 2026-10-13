"""Portable orchestration; original study sources and reference data stay immutable."""
from pathlib import Path
import argparse,hashlib,json,os,platform,shutil,subprocess,sys,time,uuid,zipfile,importlib.util,importlib.metadata
REPO=Path(__file__).resolve().parents[1]
os.environ.update(PYTHONDONTWRITEBYTECODE='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
sys.dont_write_bytecode=True

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,obj):Path(p).write_text(json.dumps(obj,indent=2)+'\n')
def run(args,cwd=None,log=None):
    print('+ '+' '.join(map(str,args)),flush=True)
    if log:
        with Path(log).open('w') as f:
            proc=subprocess.Popen(list(map(str,args)),cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            for line in proc.stdout:f.write(line);f.flush();print(line,end='',flush=True)
            if proc.wait():raise RuntimeError('Command failed; see '+str(log))
    else:subprocess.run(list(map(str,args)),cwd=cwd,check=True)
def check_reference():
    for path,digest in json.loads((REPO/'REFERENCE_SHA256.json').read_text()).items():
        if sha(REPO/path)!=digest:raise RuntimeError('Reference changed: '+path)
def native():
    if platform.system()!='Linux':raise RuntimeError('Cryptographic modes require Linux; use the supplied Docker build or Linux/WSL2')
    configured=(REPO/'.native-prefix').read_text().strip() if (REPO/'.native-prefix').exists() else str(REPO/'native/linux_x86_64')
    root=Path(os.environ.get('OQS_INSTALL_PATH',configured)).resolve()
    if not (root/'lib/liboqs.so').exists():raise RuntimeError('liboqs missing. Run bash setup.sh full --build-native')
    os.environ['OQS_INSTALL_PATH']=str(root)
    run([sys.executable,'-c','import oqs; assert all(x in oqs.get_enabled_sig_mechanisms() for x in ["ML-DSA-65","SLH_DSA_PURE_SHA2_192F"]); print("Native algorithms available")'])
    return root

def stage(output,published):
    base=Path(output).resolve();base.mkdir(parents=True,exist_ok=False);root=base/'revision';root.mkdir()
    shutil.copytree(REPO/'src/release',root/'release')
    for name in ['audit','measured','retained','results','work','logs','figures']:
        if published and (REPO/'data/published'/name).exists():shutil.copytree(REPO/'data/published'/name,root/name)
        else:(root/name).mkdir()
    (base/'tools').mkdir();shutil.copyfile(REPO/'src/replay_checks.py',base/'tools/replay_checks.py')
    shutil.copyfile(REPO/'src/make_figures.py',base/'make_figures.py')
    if published:shutil.copyfile(REPO/'notebooks/Published_Analysis_Executed.ipynb',root/'VITAL_Q_Analysis.ipynb')
    return base,root

def execute_notebook(root):
    run([sys.executable,REPO/'scripts/execute_cells.py',root],log=root/'logs/notebook.log')
    return 6

def replay(output):
    base,root=stage(output,True)
    run([sys.executable,base/'tools/replay_checks.py','--output',base/'REPLAY_REPORT.json'],log=root/'logs/replay.log')
    cells=execute_notebook(root)
    run([sys.executable,base/'make_figures.py'],log=root/'logs/figures.log')
    # Export tables and report data to a convenient top-level folder.
    write(base/'REPRODUCTION_STATUS.json',{'mode':'published numerical replay','status':'passed','notebook_cells_reexecuted':cells,'fresh_measurements':False,'figures':str(root/'figures')})
    return base

def verify(output):
    native();base,root=stage(output,True)
    run([sys.executable,root/'release/validate_results.py'],log=root/'logs/verify.log')
    write(base/'REPRODUCTION_STATUS.json',{'mode':'retained cryptographic evidence verification','status':'passed','report':json.loads((root/'audit/final_validation.json').read_text()),'fresh_measurements':False})
    return base

def load_analysis(root):
    sys.path.insert(0,str(root/'release'))
    spec=importlib.util.spec_from_file_location('portable_analysis',root/'release/analysis_v4.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

def freeze(root):
    a=load_analysis(root);dev=a.read_rows('development')
    assert len(dev)==864 and all(r['status']=='ok' for r in dev)
    models={name:a.fit([r for r in dev if r['mode']=='balanced'],cols) for name,cols in a.MODELS.items()}
    write(root/'release/models.json',models)
    write(root/'audit/development_summary.json',a.summaries(dev,models,bootstrap=False))
    write(root/'release/training_input_hashes.json',{str(p.relative_to(root)):sha(p) for p in [root/'measured/development.jsonl',root/'measured/calibration.json',root/'audit/qualification.json']})
    a.freeze(root/'release',root/'audit/freeze.json')
    write(root/'audit/freeze_receipt.json',{'local_time_unix':time.time(),'release_manifest_sha256':sha(root/'audit/freeze.json'),'human_review':'No human review claimed by this runner','trust':'Local integrity snapshot, not public preregistration or trusted time','prior_results_known':True,'evaluation_size_previously_exercised':True})
    target=root.parent/'pre_evaluation_snapshot.zip'
    with zipfile.ZipFile(target,'x',zipfile.ZIP_DEFLATED) as z:
        for folder in ['release','audit','measured']:
            for p in sorted((root/folder).rglob('*')):
                if p.is_file():z.write(p,p.relative_to(root))
    with target.open('rb') as f:os.fsync(f.fileno())
    with zipfile.ZipFile(target) as z:assert z.testzip() is None
    # Compatibility filename expected by the original campaign; provider is explicitly local.
    write(root/'audit/external_snapshot_receipt.json',{'saved_before_evaluation':True,'receipt_recorded_unix':time.time(),'provider':'local filesystem; not external hosting','snapshot_sha256':sha(target),'public_preregistration':False,'trusted_timestamp':False,'independent_backup':False})

def fresh(output,smoke=False):
    native_root=native();base,root=stage(output,False)
    for name in ['models.json','training_input_hashes.json','coefficients.json','crypto_primer.json','environment.json']:
        p=root/'release'/name
        if p.exists():p.unlink()
    schedule=json.loads((root/'release/schedule.json').read_text());prefix=('smoke-' if smoke else 'fresh-')+uuid.uuid4().hex[:12]
    sizes={1000:32,10000:128,100000:256} if smoke else {1000:1000,10000:10000,100000:100000}
    for row in schedule['histories']:
        row['block_id']=prefix+'-'+row['block_id'];row['history_id']=prefix+'-'+row['history_id']
        row['n']=sizes[row['n']];row['query_id']%=row['n']
    write(root/'release/schedule.json',schedule)
    amendment={'kind':'smoke workflow validation' if smoke else 'fresh full-scale reproduction','source_protocol':'VITAL_Q_LINUX_4_2','created_unix':time.time(),'sizes':sizes,'histories':162,'fresh_block_ids':True,'checkpoint':'synchronous local filesystem ZIP after each completed history','scope':'Same source algorithms and measurement boundaries; new keys, inputs, timings and model calibration. Local checkpoint is not an independent backup or trusted timestamp.','observation_persistence':'Atomic checksummed journal of all 12 actual measurements per history, aggregate rebuilt from journals; workers stopped before commit','hosted_service_required':False,'smoke_is_paper_replication':False}
    protocol=json.loads((root/'release/protocol.json').read_text());protocol['portable_execution_amendment']=amendment
    protocol['development']['sizes']=[sizes[1000],sizes[10000]];protocol['evaluation']['sizes']=[sizes[100000]]
    for key in ['author_constraint','development_restart','recovery_amendment','interruption_recovery']:protocol.pop(key,None)
    protocol['execution_isolation']=amendment['checkpoint'];protocol['new_protocol_created_unix']=time.time()
    write(root/'release/protocol.json',protocol);write(root/'audit/PORTABILITY_AMENDMENT.json',amendment)
    if smoke:
        # Only evaluation display/export key changes; all numerical functions stay unchanged.
        p=root/'release/analysis_v4.py';t=p.read_text();assert t.count("['100000']")==2
        p.write_text(t.replace("['100000']","['256']"))
        p=base/'make_figures.py';t=p.read_text();assert t.count("['100000']")==1;p.write_text(t.replace("['100000']","['256']"))
    packages={n:importlib.metadata.version(n) for n in ['numpy','scipy','cryptography','liboqs-python','pqcrypto']}
    write(root/'release/environment.json',{'python':sys.version,'platform':platform.platform(),'machine':platform.machine(),'cpu':next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),platform.processor()),'packages':packages,'native_sha256':sha(native_root/'lib/liboqs.so'),'execution':'Portable local runner; not independent human verification'})
    primer='from crypto_backend import Key\nimport json\nfrom pathlib import Path\nrows=[]\nfor alg in (1,2,3):\n k=Key(alg);msg=b"VITAL-Q untimed worker primer";rows.append(dict(alg=alg,public=k.public.hex(),message=msg.hex(),signature=k.sign(msg).hex()));k.close()\nPath("crypto_primer.json").write_text(json.dumps(rows))\n'
    run([sys.executable,'-c',primer],cwd=root/'release',log=root/'logs/primer.log')
    # Persist complete observations from the original in-memory results only.
    shutil.copyfile(REPO/'scripts/portable_io.py',root/'release/portable_io.py')
    p=root/'release/campaign.py';text=p.read_text()
    old="append_log(ROOT/'measured'/f'{phase}.jsonl',obs);observations.append(obs)"
    assert text.count(old)==1
    text=text.replace(old,'observations.append(obs)')
    old="            status.update(status='ok',finished_unix=time.time(),campaign_seconds=archive['campaign_seconds'],"
    assert text.count(old)==1
    text=text.replace(old,"            from portable_io import commit_observations\n            commit_observations(ROOT,phase,hid,observations)\n"+old)
    p.write_text(text)
    os.environ['VITAL_Q_CHECKPOINT_COMMAND']=json.dumps([sys.executable,str(REPO/'scripts/checkpoint.py'),str(root)])
    for name in ['test_timing.py','qualification.py','calibration.py']:
        run([sys.executable,root/'release'/name],log=root/'logs'/(name+'.log'))
    run([sys.executable,REPO/'scripts/checkpoint.py',root])
    run([sys.executable,root/'release/campaign.py','development'],log=root/'logs/development.log')
    freeze(root)
    run([sys.executable,root/'release/campaign.py','evaluation'],log=root/'logs/evaluation.log')
    run([sys.executable,root/'release/analysis_v4.py','analyze'],log=root/'logs/analysis.log')
    run([sys.executable,root/'release/validate_results.py'],log=root/'logs/validation.log')
    run([sys.executable,base/'make_figures.py'],log=root/'logs/figures.log')
    run([sys.executable,REPO/'scripts/checkpoint.py',root])
    write(base/'REPRODUCTION_STATUS.json',{'status':'passed','mode':amendment['kind'],'sizes':sizes,'report':json.loads((root/'audit/final_validation.json').read_text()),'published_results_overwritten':False,'new_empirical_results_for_manuscript':False})
    return base

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['replay','verify','smoke','fresh','all'])
    p.add_argument('--output',type=Path,help='New output directory; an existing path is refused')
    a=p.parse_args();check_reference()
    out=a.output or REPO/'runs'/(a.mode+'-'+time.strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6])
    if a.mode=='all':
        out.mkdir(parents=True,exist_ok=False);replay(out/'replay');verify(out/'verify');fresh(out/'fresh')
    elif a.mode=='replay':replay(out)
    elif a.mode=='verify':verify(out)
    else:fresh(out,smoke=a.mode=='smoke')
    check_reference();print('COMPLETE: '+str(out.resolve()),flush=True)
if __name__=='__main__':main()
