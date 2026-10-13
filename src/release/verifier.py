"""Public-evidence verifier. Does not import archive_builder or campaign decisions."""
import hashlib,json,struct
from pathlib import Path
from crypto_backend import verify,PK_LEN,SIG_LEN
from research_tools import FEATURES
class EvidenceError(ValueError):pass
class Meter:
 def __init__(self):self.counts=[0]*23
 def add(self,name,value=1):self.counts[FEATURES.index(name)]+=value
 def digest(self,branch,data):
  name='sha384' if branch else 'sha256';self.add(name+'_calls');self.add(name+'_bytes',len(data))
  return (hashlib.sha384 if branch else hashlib.sha256)(data).digest()
 def read(self,f,n):
  self.add('read_calls');b=f.read(n);self.add('read_bytes',len(b))
  if len(b)!=n:raise EvidenceError('truncated input')
  return b
 def decode(self,b):self.add('decode_objects');self.add('decode_bytes',len(b))

def canonical_manifest(data,meter=None):
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise EvidenceError('duplicate JSON key')
   d[k]=v
  return d
 try:
  m=json.loads(data,object_pairs_hook=unique)
  encoded=json.dumps(m,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
 except (ValueError,UnicodeDecodeError,TypeError) as e:raise EvidenceError('invalid JSON') from e
 if meter:meter.add('encode_objects');meter.add('encode_bytes',len(encoded))
 if len(data)!=1024 or encoded!=data or not isinstance(m.get('id'),int) or not isinstance(m.get('padding'),str):raise EvidenceError('noncanonical manifest')
 for k in ('payload_sha256','code_sha256','config_sha256','environment_sha256'):
  if not isinstance(m.get(k),str) or len(m[k])!=64:raise EvidenceError('missing manifest digest')
  try:bytes.fromhex(m[k])
  except ValueError:raise EvidenceError('invalid digest')
 return m

def parse_header(b,policy,meter):
 meter.decode(b)
 if len(b)!=64:raise EvidenceError('header length')
 magic,v,arm,mode,g,n,batch,qid,epoch,hid=struct.unpack('>8sBBBBIIIQ32s',b)
 if magic!=b'PQARCH02' or v!=2 or arm not in (1,2,3) or mode not in (1,2) or g not in range(6) or not 1<=n<2**20 or batch!=4096:raise EvidenceError('invalid header')
 if (mode==1 and qid!=2**32-1) or (mode==2 and not 0<=qid<n):raise EvidenceError('query ID')
 if (hid.hex(),arm,n,epoch)!=(policy['history_id'],policy['arm'],policy['n'],policy['epoch']):raise EvidenceError('untrusted history')
 return dict(arm=arm,mode=mode,g=g,n=n,qid=qid,epoch=epoch,hid=hid)

def decode_frame(frame,body,meter):
 meter.decode(frame+body)
 magic,v,t,res,oid,size=struct.unpack('>4sBBHII',frame)
 if magic!=b'PQOB' or v!=2 or t not in range(1,6) or res or len(body)!=size:raise EvidenceError('invalid frame')
 return t,oid,body

def read_object(f,meter):
 frame=meter.read(f,16)
 # Validate before trusting the untrusted length.
 magic,v,t,res,oid,size=struct.unpack('>4sBBHII',frame)
 if magic!=b'PQOB' or v!=2 or t not in range(1,6) or res or not 1<=size<=20_000_000:raise EvidenceError('invalid frame header')
 body=meter.read(f,size)
 return decode_frame(frame,body,meter)

def root_from_leaves(leaves,branch,meter):
 level=leaves
 while len(level)>1:
  level=[meter.digest(branch,b'\x01'+level[i]+level[i+1]) if i+1<len(level) else level[i] for i in range(0,len(level),2)]
 return level[0]

def visit(subject):
 # One abstract top-level visit; bookkeeping remains inside observed wall time.
 return subject

def verify_proof(path,policy,return_manifests=False,*,expected=None):
 if expected is None:raise EvidenceError("Caller must supply requested checkpoint, query mode and record ID")
 meter=Meter(); keys={};manifests=[];roots={};previous={}
 with open(path,'rb',buffering=0) as f:
  h=parse_header(meter.read(f,64),policy,meter)
  arm,mode,g,n,qid,epoch,hid=(h[k] for k in ('arm','mode','g','n','qid','epoch','hid'))
  requested_g,requested_query,requested_id=expected
  if requested_query not in ('full','selective') or not 0<=requested_id<n:raise EvidenceError('invalid external query')
  if (g,mode,qid)!=(requested_g,1 if requested_query=='full' else 2,2**32-1 if requested_query=='full' else requested_id):raise EvidenceError('proof does not answer the external request')
  branches=(0,1) if arm==3 else (0,)
  ids=range(n) if mode==1 else (qid,)
  leaves={b:[] for b in branches}
  for idx in ids:
   t,oid,body=read_object(f,meter)
   if (t,oid)!=(1,idx):raise EvidenceError('manifest order or ID')
   manifest=canonical_manifest(body,meter)
   if manifest['id']!=idx:raise EvidenceError('manifest index')
   if return_manifests:manifests.append(manifest)
   for branch in branches:leaves[branch].append(meter.digest(branch,b'\x00'+idx.to_bytes(8,'big')+body))
  subjects=list(range(n if arm==1 else (n+4095)//4096)) if mode==1 else [qid if arm==1 else qid//4096]
  if arm==1:
   roots[0]=dict(zip(subjects,leaves[0]))
  elif mode==1:
   for branch in branches:
    roots[branch]={i//4096:root_from_leaves(leaves[branch][i:i+4096],branch,meter) for i in range(0,n,4096)}
  for generation in range(g+1):
   for branch in branches:
    t,oid,body=read_object(f,meter);alg=3 if branch else (1 if generation==0 else 2)
    if t!=2 or oid!=(branch<<28)|generation or len(body)!=63+PK_LEN[alg]:raise EvidenceError('enrollment object')
    fields=struct.unpack('>8sBBBBIQ16s20s3s',body[:63])
    domain,v,a,b,al,gen,issued,kid,hist,res=fields
    pub=body[63:]
    if (domain,v,a,b,al,gen,issued,hist,res)!=(b'PQKEY002',2,arm,branch,alg,generation,epoch+100*generation,hid[:20],b'\0'*3):raise EvidenceError('enrollment fields')
    if kid!=meter.digest(0,b'PQKID002'+pub)[:16]:raise EvidenceError('key identifier')
    enrolled=policy['keys'].get(f'{branch}:{generation}')
    if enrolled is None or enrolled!=pub.hex():raise EvidenceError('untrusted key')
    keys[branch,generation]=(kid,pub,alg)
  if mode==2 and arm!=1:
   for branch in branches:
    t,oid,body=read_object(f,meter);width=48 if branch else 32;batchid=qid//4096;first=batchid*4096;b=min(4096,n-first)
    if t!=5 or oid!=(branch<<28)|batchid or len(body)<24:raise EvidenceError('inclusion object')
    v,br,w,res,bi,fi,le,cnt,rsv=struct.unpack('>BBBBIIIII',body[:24])
    if (v,br,w,res,bi,fi,le,rsv)!=(2,branch,width,0,batchid,first,b,0) or len(body)!=24+cnt*width:raise EvidenceError('inclusion metadata')
    value=leaves[branch][0];j=qid-first;remaining=b;off=24
    while remaining>1:
     if (j^1)<remaining:
      sibling=body[off:off+width]
      if len(sibling)!=width:raise EvidenceError('missing sibling')
      value=meter.digest(branch,b'\x01'+(sibling+value if j%2 else value+sibling));off+=width
     j//=2;remaining=(remaining+1)//2
    if off!=len(body):raise EvidenceError('extra siblings')
    roots[branch]={batchid:value}
  eligibility={b:True for b in branches};breaks={int(k):v for k,v in policy.get('algorithm_breaks',{}).items()}
  for generation in range(g+1):
   for branch in branches:
    kid,pub,alg=keys[branch,generation];width=48 if branch else 32;msglen=68+2*width
    for subject in subjects:
     if generation==0:visit(subject);meter.add('subject_visits')
     t,oid,body=read_object(f,meter)
     if t!=3 or oid!=((branch<<28)|(generation<<20)|subject) or len(body)!=msglen+SIG_LEN[alg]:raise EvidenceError('token ID or length')
     fields=struct.unpack('>8sBBBBIQQ16s20s',body[:68])
     if fields!=(b'PQTOKEN2',2,arm,branch,alg,generation,subject,epoch+100*generation,kid,hid[:20]):raise EvidenceError('token metadata')
     if body[68:68+width]!=roots[branch][subject]:raise EvidenceError('target mismatch')
     if body[68+width:msglen]!=previous.get((branch,subject),b'\0'*width):raise EvidenceError('predecessor mismatch')
     meter.add({1:'ecdsa_verify',2:'mldsa_verify',3:'slhdsa_verify'}[alg])
     if not verify(alg,pub,body[:msglen],body[msglen:]):raise EvidenceError('invalid signature')
     if generation<g:previous[branch,subject]=meter.digest(branch,b'\x02'+body)
    issued=epoch+100*generation
    deadline=min(breaks.get(alg,float('inf')),policy.get('key_lifetime',150)+issued)
    needs_until=epoch+100*(generation+1) if generation<g else policy.get('evaluation_time',epoch+100*g+1)
    if needs_until>=deadline:eligibility[branch]=False
  meter.add('read_calls')
  if f.read(1):raise EvidenceError('extra object or bytes')
 if not any(eligibility.values()):raise EvidenceError('no historically eligible branch')
 return {'accepted':True,'counts':meter.counts,'branch_eligible':eligibility,'manifests':manifests}

def payload_audit(manifests,root):
 import time
 start=time.perf_counter();seen=set();bad=[];total=0;objects=0
 root=Path(root).resolve()
 for m in manifests:
  digest=m['payload_sha256']
  if digest in seen:continue
  seen.add(digest);p=(root/m['payload_path']).resolve()
  if not p.is_relative_to(root):raise EvidenceError('payload path escape')
  try:
   data=p.read_bytes();total+=len(data);objects+=1
   if hashlib.sha256(data).hexdigest()!=digest:bad.append(m['id'])
  except OSError:bad.append(m['id'])
 return {'accepted':not bad,'failed_record_ids':bad,'unique_objects':objects,'bytes_read':total,'hashes':objects,'seconds':time.perf_counter()-start}
