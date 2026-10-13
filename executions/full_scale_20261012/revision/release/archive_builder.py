"""Archive construction; never used for verifier acceptance decisions."""
import os,json,hashlib,struct,time,secrets
from pathlib import Path
from array import array
from crypto_backend import Key,PK_LEN,SIG_LEN
from research_tools import ledger,path_length,FEATURES
ARM={'N':1,'E':2,'D':3};B=4096
FRAME=struct.Struct('>4sBBHII');HEADER=struct.Struct('>8sBBBBIIIQ32s')
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def manifest(obj):
 x=dict(obj,padding='');remaining=1024-len(canonical(x))
 if remaining<0:raise ValueError('manifest too long')
 x['padding']=' '*remaining;result=canonical(x);assert len(result)==1024;return result

def synthetic_manifests(n,seed):
 common={'code_sha256':hashlib.sha256(b'PQ synthetic v2').hexdigest(),'config_sha256':hashlib.sha256(str(seed).encode()).hexdigest(),'environment_sha256':hashlib.sha256(b'synthetic environment v2').hexdigest(),'parents':[]}
 return [manifest(dict(common,id=i,payload_sha256=hashlib.sha256(f'{seed}/{i}'.encode()).hexdigest(),payload_path=f'synthetic/{i}',record_kind='synthetic')) for i in range(n)]
def pack_frame(t,oid,body):return FRAME.pack(b'PQOB',2,t,0,oid,len(body))+body
def digest(branch,b):return (hashlib.sha384 if branch else hashlib.sha256)(b).digest()
def tree(manifests,first,branch):
 levels=[[digest(branch,b'\0'+(first+i).to_bytes(8,'big')+m) for i,m in enumerate(manifests)]]
 while len(levels[-1])>1:
  v=levels[-1];levels.append([digest(branch,b'\1'+v[i]+v[i+1]) if i+1<len(v) else v[i] for i in range(0,len(v),2)])
 return levels

def path_bytes(levels,index):
 siblings=[]
 for lev in levels[:-1]:
  if (index^1)<len(lev):siblings.append(lev[index^1])
  index//=2
 return b''.join(siblings),len(siblings)
class Writer:
 def __init__(self,path,header):
  self.path=Path(path);self.file=open(path,'xb',buffering=0);self.file.write(header);os.fsync(self.file.fileno())
  d=os.open(self.path.parent,os.O_DIRECTORY);os.fsync(d);os.close(d)
  self.pending=0;self.trace=[];self.pending_records={0:0,1:0};self.gen=-1;self.start=time.perf_counter();self.offset=64;self.objects=0
 def append(self,t,oid,body,credit=None):
  raw=pack_frame(t,oid,body);off=self.offset
  wrote=self.file.write(raw)
  if wrote!=len(raw):raise OSError('short archive write')
  self.offset+=wrote;self.pending+=wrote;self.objects+=1
  if credit:self.pending_records[credit[0]]+=credit[1]
  if self.pending>=4*1024**2:self.flush()
  return off
 def flush(self):
  if not self.pending:return
  t=time.perf_counter();os.fsync(self.file.fileno());end=time.perf_counter()
  self.trace.append({'generation':self.gen,'completed_offset':self.offset,'objects':self.objects,'elapsed_seconds':end-self.start,'barrier_seconds':end-t,'bytes':self.pending,'new_records':dict(self.pending_records)})
  self.pending=0;self.pending_records={0:0,1:0}
 def close(self):self.flush();self.file.close()

def build_archive(path,manifests,arm,generations=6,epoch=1000000):
 if arm not in ARM or not manifests or len(manifests)>=2**20 or not 1<=generations<=6:raise ValueError('invalid archive parameters')
 n=len(manifests);a=ARM[arm];hid=secrets.token_bytes(32);branches=(0,1) if arm=='D' else (0,)
 header=HEADER.pack(b'PQARCH02',2,a,0,generations-1,n,B,2**32-1,epoch,hid)
 w=Writer(path,header);w.gen=0
 keys_index={};token_index={};tree_index={};previous={};roots={};selected_trees={}
 for i,m in enumerate(manifests):
  if len(m)!=1024:raise ValueError('manifest width')
  w.append(1,i,m)
 subjects=n if arm=='N' else (n+B-1)//B
 policy={'history_id':hid.hex(),'arm':a,'n':n,'epoch':epoch,'keys':{},'algorithm_breaks':{'1':epoch+150},'key_lifetime':150}
 for g in range(generations):
  w.gen=g
  for branch in branches:
   alg=3 if branch else (1 if g==0 else 2);width=48 if branch else 32;key=Key(alg)
   kid=hashlib.sha256(b'PQKID002'+key.public).digest()[:16]
   kb=struct.pack('>8sBBBBIQ16s20s3s',b'PQKEY002',2,a,branch,alg,g,epoch+100*g,kid,hid[:20],b'\0'*3)+key.public
   keys_index[branch,g]=w.append(2,(branch<<28)|g,kb)
   policy['keys'][f'{branch}:{g}']=key.public.hex()
   offsets=array('Q');token_index[branch,g]=offsets
   for s in range(subjects):
    credit=1 if arm=='N' else min(B,n-s*B)
    if g==0:
     if arm=='N':root=digest(branch,b'\0'+s.to_bytes(8,'big')+manifests[s])
     else:
      first=s*B;levels=tree(manifests[first:first+B],first,branch);root=levels[-1][0]
      stored=levels[0]+[x for j,lev in enumerate(levels[1:]) for x in lev[:len(levels[j])//2]];nodecount=len(stored);assert nodecount==2*credit-1
      tb=struct.pack('>BBBBIIIII',2,branch,width,0,s,first,credit,nodecount,0)+b''.join(stored)
      tree_index[branch,s]=w.append(4,(branch<<28)|s,tb)
     roots[branch,s]=root
    msg=struct.pack('>8sBBBBIQQ16s20s',b'PQTOKEN2',2,a,branch,alg,g,s,epoch+100*g,kid,hid[:20])+roots[branch,s]+previous.get((branch,s),b'\0'*width)
    body=msg+key.sign(msg);offsets.append(w.append(3,(branch<<28)|(g<<20)|s,body,(branch,credit)))
    if g<generations-1:previous[branch,s]=digest(branch,b'\2'+body)
   key.close()
  w.flush()
 w.close();seconds=time.perf_counter()-w.start
 expected=ledger(n,generations)['archive_bytes'][arm]
 if Path(path).stat().st_size!=expected:raise AssertionError('archive ledger mismatch')
 return {'path':str(path),'arm':arm,'n':n,'generations':generations,'history_id':hid.hex(),'epoch':epoch,'keys_index':keys_index,'token_index':token_index,'tree_index':tree_index,'policy':policy,'trace':w.trace,'archive_bytes':expected,'campaign_seconds':seconds}

def read_raw(f,off):
 f.seek(off);head=f.read(16)
 if len(head)!=16:raise ValueError('bad archive index')
 size=FRAME.unpack(head)[-1];b=f.read(size)
 if len(b)!=size:raise ValueError('truncated archive')
 return head+b

def construct_proof(archive,path,g,query,qid):
 start=time.perf_counter();arm=archive['arm'];a=ARM[arm];n=archive['n'];branches=(0,1) if arm=='D' else (0,)
 if query not in ('full','selective') or not 0<=g<archive['generations'] or not 0<=qid<n:raise ValueError('invalid proof request')
 mode=1 if query=='full' else 2;subjects=list(range(n if arm=='N' else (n+B-1)//B)) if query=='full' else [qid if arm=='N' else qid//B]
 with open(archive['path'],'rb',buffering=0) as f,open(path,'xb',buffering=0) as out:
  out.write(HEADER.pack(b'PQARCH02',2,a,mode,g,n,B,2**32-1 if mode==1 else qid,archive['epoch'],bytes.fromhex(archive['history_id'])))
  for idx in range(n) if mode==1 else (qid,):out.write(read_raw(f,64+idx*1040))
  for gen in range(g+1):
   for branch in branches:out.write(read_raw(f,archive['keys_index'][branch,gen]))
  if mode==2 and arm!='N':
   for branch in branches:
    s=qid//B;first=s*B;b=min(B,n-first);width=48 if branch else 32
    raw=read_raw(f,archive['tree_index'][branch,s]);nodes=raw[40:];pos=b*width
    levels=[[nodes[i*width:(i+1)*width] for i in range(b)]]
    while len(levels[-1])>1:
     prev=levels[-1];cnt=len(prev)//2;lev=[nodes[pos+i*width:pos+(i+1)*width] for i in range(cnt)];pos+=cnt*width
     if len(prev)%2:lev.append(prev[-1])
     levels.append(lev)
    body,cnt=path_bytes(levels,qid-first)
    body=struct.pack('>BBBBIIIII',2,branch,width,0,s,first,b,cnt,0)+body
    out.write(pack_frame(5,(branch<<28)|s,body))
  for gen in range(g+1):
   for branch in branches:
    for subject in subjects:out.write(read_raw(f,archive['token_index'][branch,gen][subject]))
 return {'construction_seconds':time.perf_counter()-start,'proof_bytes':Path(path).stat().st_size}

def predicted_counts(arm,n,g,query,qid):
 # Independent arithmetic recurrence: no observed times or instrumentation input.
 c=dict.fromkeys(FEATURES,0);k=(n+B-1)//B;G=g+1;m=n if query=='full' else 1;subjects=(n if arm=='N' else k) if query=='full' else 1;branches=2 if arm=='D' else 1
 ell=path_length(min(B,n-(qid//B)*B),qid%B);L=ledger(n,G,ell)
 keybytes=144+2031*g+(127*G if arm=='D' else 0)
 tokenbytes=subjects*(212+3457*g+(35844*G if arm=='D' else 0))
 pathbytes=(40+32*ell+(40+48*ell if arm=='D' else 0)) if query=='selective' and arm!='N' else 0
 npath=branches if pathbytes else 0
 objects=m+branches*G+npath+subjects*G*branches;total=64+1040*m+keybytes+tokenbytes+pathbytes
 c['ecdsa_verify']=subjects;c['mldsa_verify']=subjects*g;c['slhdsa_verify']=subjects*G if arm=='D' else 0
 c['encode_objects']=m;c['encode_bytes']=1024*m;c['decode_objects']=1+objects;c['decode_bytes']=total
 c['read_calls']=2+2*objects;c['read_bytes']=total;c['subject_visits']=subjects*branches
 for branch in range(branches):
  name='sha384' if branch else 'sha256';width=48 if branch else 32
  internals=0 if arm=='N' else ((n-k) if query=='full' else ell)
  c[name+'_calls']+=m+internals+subjects*g
  c[name+'_bytes']+=1033*m+(1+2*width)*internals
  if g:
   c[name+'_bytes']+=subjects*((35829*g) if branch else (197+3442*(g-1)))
 c['sha256_calls']+=branches*G;c['sha256_bytes']+=73+1960*g+(56*G if arm=='D' else 0)
 return [c[f] for f in FEATURES],total

def warm_file(path):
 with open(path,'rb') as f:
  while f.read(4*1024**2):pass
