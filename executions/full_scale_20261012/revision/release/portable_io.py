"""Transactional history journals for portable collection, outside query timing."""
from pathlib import Path
import json,hashlib,os,tempfile

def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
def atomic_write(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix=path.name+'.',suffix='.tmp',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
        d=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(d)
        finally:os.close(d)
    finally:
        if os.path.exists(name):os.unlink(name)

def rebuild(root,phase):
    root=Path(root);folder=root/'measured/per_history'/phase
    if not folder.exists():return False
    combined=[];ids=set()
    for p in sorted(folder.glob('*.json')):
        obj=json.loads(p.read_text());rows=obj['observations']
        if hashlib.sha256(canonical(rows)).hexdigest()!=obj['sha256']:raise RuntimeError('History journal checksum failure: '+str(p))
        expected={(g,q,m) for g in [0,2,5] for q in ['full','selective'] for m in ['balanced','isolated']}
        if len(rows)!=12 or {(r['renewals'],r['query'],r['mode']) for r in rows}!=expected:raise RuntimeError('Incomplete journal: '+str(p))
        if obj['history_id'] in ids or any(r['history_id']!=obj['history_id'] or r['phase']!=phase for r in rows):raise RuntimeError('Journal identity mismatch')
        ids.add(obj['history_id']);combined.extend(rows)
    data=b''.join(canonical(row)+b'\n' for row in combined);target=root/'measured'/f'{phase}.jsonl'
    changed=not target.exists() or target.read_bytes()!=data
    if changed:atomic_write(target,data)
    return changed

def commit_observations(root,phase,history_id,rows):
    root=Path(root);p=root/'measured/per_history'/phase/(history_id+'.json')
    if p.exists():raise FileExistsError('History already journaled: '+str(p))
    obj={'history_id':history_id,'observations':rows,'sha256':hashlib.sha256(canonical(rows)).hexdigest()}
    atomic_write(p,canonical(obj)+b'\n');rebuild(root,phase)
