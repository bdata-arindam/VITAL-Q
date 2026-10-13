"""Portable synchronous local checkpoint; called only after workers stop."""
from pathlib import Path
import os,sys,json,zipfile,hashlib,time,collections
from portable_io import rebuild

def save(root):
    root=Path(root).resolve(); folder=root.parent/'checkpoints';folder.mkdir(exist_ok=True)
    # Reject lost/duplicated rows before replacing a previously valid recovery copy.
    for phase in ['development','evaluation']:
        if rebuild(root,phase):print(json.dumps({'aggregate_rebuilt_from_verified_journals':phase}),flush=True)
    history=root/'measured/histories.jsonl'
    if history.exists():
        histories=[json.loads(line) for line in history.read_text().splitlines()]
        for phase in ['development','evaluation']:
            path=root/'measured'/f'{phase}.jsonl'
            rows=[json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
            grouped=collections.defaultdict(list)
            for row in rows:grouped[row['history_id']].append(row)
            selected=[h for h in histories if h['phase']==phase]
            if set(grouped)!={h['history_id'] for h in selected}:raise RuntimeError(f'{phase}: history/observation identifiers differ')
            expected={(g,q,m) for g in [0,2,5] for q in ['full','selective'] for m in ['balanced','isolated']}
            for h in selected:
                found=grouped[h['history_id']]
                keys={(r['renewals'],r['query'],r['mode']) for r in found}
                if h['status']!='ok' or len(found)!=12 or keys!=expected:
                    raise RuntimeError(f"Incomplete or duplicated measurements for {h['history_id']}: {len(found)}/12")
    target=folder/'latest.zip';temp=folder/'latest.tmp' 
    manifest={}
    with zipfile.ZipFile(temp,'w',zipfile.ZIP_DEFLATED,compresslevel=1) as z:
        for name in ['release','audit','measured','retained','results']:
            for p in sorted((root/name).rglob('*')):
                if p.is_file() and '__pycache__' not in p.parts:
                    data=p.read_bytes();rel=p.relative_to(root).as_posix()
                    z.writestr(rel,data);manifest[rel]=hashlib.sha256(data).hexdigest()
        z.writestr('CHECKPOINT_SHA256.json',json.dumps(manifest,sort_keys=True))
    with temp.open('rb') as f:os.fsync(f.fileno())
    with zipfile.ZipFile(temp) as z:
        if z.testzip() is not None:raise RuntimeError('Checkpoint integrity failure')
    os.replace(temp,target)
    fd=os.open(folder,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    receipt={'provider':'local filesystem','path':str(target),'saved_unix':time.time(),'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'files':len(manifest),'independent_backup':False,'trusted_timestamp':False}
    (root/'audit/local_checkpoint.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'checkpoint':'ok','files':len(manifest)}),flush=True)

if __name__=='__main__':save(sys.argv[1])
