"""Version 4 warm-cache campaign with balanced orders and isolated workers.

Proof creation, file warming, explicit GC, process startup, cryptographic priming,
result checks and returned-result disposal all lie outside the query timer.
Ordinary verifier internal cleanup remains inside the public function call.
"""
import os,json,hashlib,time,shutil,resource,traceback,argparse,sys,subprocess
from pathlib import Path
from archive_builder import build_archive,synthetic_manifests,construct_proof,predicted_counts
from research_tools import sha,verify_freeze
ROOT=Path(__file__).resolve().parent.parent

def append_log(path,obj):
    with open(path,'a') as f:
        f.write(json.dumps(obj,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())

def worker():
    return subprocess.Popen([sys.executable,str(ROOT/'release/query_worker.py')],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)

def ask(process,request):
    process.stdin.write(json.dumps(request)+'\n');process.stdin.flush()
    response=process.stdout.readline()
    if not response:raise RuntimeError('query worker terminated')
    return json.loads(response)

def isolated(request):
    result=subprocess.run([sys.executable,str(ROOT/'release/query_worker.py'),'--once'],
        input=json.dumps(request)+'\n',text=True,capture_output=True,check=True)
    # liboqs emits its faulthandler notice on stderr, never measurement stdout.
    return json.loads(result.stdout)

def run_phase(phase):
    checkpoint_command=json.loads(os.environ['VITAL_Q_CHECKPOINT_COMMAND'])
    if phase=='evaluation':
        verify_freeze(ROOT/'release',ROOT/'audit/freeze.json')
        assert (ROOT/'audit/external_snapshot_receipt.json').exists(), 'Save pre-evaluation snapshot first'
    schedule=json.loads((ROOT/'release/schedule.json').read_text())['histories']
    rows=[r for r in schedule if r['phase']==phase]
    status_path=ROOT/'measured/histories.jsonl'
    done={r['history_id']:r for r in map(json.loads,status_path.read_text().splitlines())} if status_path.exists() else {}
    for row in rows:
        hid=row['history_id']
        if hid in done:
            if done[hid]['status']!='ok':raise RuntimeError('Failed histories require a disclosed protocol amendment')
            continue
        # Peak: one six-generation archive and one full proof. No concurrent writers.
        needed=2*(64+1040*row['n']+10363+row['n']*17497)+120*1024**2
        if shutil.disk_usage(ROOT).free<needed:raise RuntimeError(f'Insufficient free disk for {hid}: need {needed}')
        dest=ROOT/'work'/hid;dest.mkdir(exist_ok=False)
        blockseed=int.from_bytes(hashlib.sha256(row['block_id'].encode()).digest()[:8],'big')
        manifests=synthetic_manifests(row['n'],blockseed)
        status=dict(row,status='running',started_unix=time.time(),manifest_set_sha256=hashlib.sha256(b''.join(manifests)).hexdigest())
        append_log(ROOT/'measured/events.jsonl',status)
        process=None
        try:
            archive=build_archive(dest/'archive.pqa',manifests,row['arm'],6)
            del manifests
            policy_path=dest/'policy.json';policy_path.write_text(json.dumps(archive['policy'],sort_keys=True))
            retained=ROOT/'retained'/hid;retained.mkdir()
            shutil.copyfile(policy_path,retained/'policy.json')
            (ROOT/'measured'/f'{hid}.barriers.json').write_text(json.dumps(archive['trace'],sort_keys=True))
            process=worker();previous=None;observations=[]
            for position,task in enumerate(row['task_order']):
                g,q=task
                proof=dest/'query.pqp'
                counts,expected=predicted_counts(row['arm'],row['n'],g,q,row['query_id'])
                construction=construct_proof(archive,proof,g,q,row['query_id'])
                assert construction['proof_bytes']==expected
                request={'proof_path':str(proof),'policy_path':str(policy_path),'expected':[g,q,row['query_id']],'counts':counts}
                proof_hash=sha(proof)
                for mode_position,mode in enumerate(row['mode_order']):
                    result=ask(process,request) if mode=='balanced' else isolated(request)
                    obs={k:row[k] for k in ('phase','block_id','history_id','arm','n','query_id')}
                    obs.update(renewals=g,query=q,mode=mode,mode_position=mode_position,position=position,
                        predecessor=previous if mode=='balanced' else None,seconds=result['seconds'],
                        counts=counts,status='ok',bytes_match=True,observed_counts_match=True,
                        observed_unix=result['observed_unix'],worker_pid=result['pid'],proof_sha256=proof_hash,**construction)
                    append_log(ROOT/'measured'/f'{phase}.jsonl',obs);observations.append(obs)
                previous=[g,q]
                if q=='selective':shutil.copyfile(proof,retained/f'selective-R{g}.pqp')
                proof.unlink()
            process.stdin.close();assert process.wait()==0;process=None
            status.update(status='ok',finished_unix=time.time(),campaign_seconds=archive['campaign_seconds'],
                archive_bytes=archive['archive_bytes'],archive_sha256=sha(dest/'archive.pqa'),
                condition_observations=len(observations),max_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
                barrier_count=len(archive['trace']),retained='all three selective proofs and public enrollment policy')
            # Full archives are regenerable, deliberately not retained under this disk profile.
            shutil.rmtree(dest)
            append_log(status_path,status)
            print(json.dumps({'history':hid,'status':'ok','elapsed_seconds':round(status['finished_unix']-status['started_unix'],2),
                'verification_seconds':round(sum(o['seconds'] for o in observations),2)}),flush=True)
        except Exception as exc:
            if process is not None:process.kill();process.wait()
            status.update(status='failed',reason=repr(exc),traceback=traceback.format_exc(),finished_unix=time.time())
            append_log(status_path,status);raise
        # Measurement workers are stopped. A failed save aborts before the next
        # history; it must not relabel a valid measurement as a verifier failure.
        subprocess.run(checkpoint_command,check=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('phase',choices=['development','evaluation'])
    run_phase(parser.parse_args().phase)
