"""Independent measured component design. Never uses development/held-out timings."""
import json,os,time,tempfile,random,struct,hashlib
from pathlib import Path
from crypto_backend import Key,verify
from archive_builder import manifest,pack_frame,synthetic_manifests,canonical
from verifier import Meter,decode_frame,visit
from research_tools import FEATURES,write_json,fit_command
ROOT=Path(__file__).resolve().parent.parent

def run():
 rows=[];warmups=[];rng=random.Random(70431)
 def measure(block,name,counts,fn):
  fn();start=time.perf_counter_ns();fn();seconds=(time.perf_counter_ns()-start)/1e9
  row={'block_id':f'cal-{block:02d}','component':name,'counts':[counts.get(f,0) for f in FEATURES],'seconds':seconds}
  rows.append(row)
 with tempfile.TemporaryDirectory(dir=ROOT/'work') as td:
  p=Path(td)/'io.bin';p.write_bytes(b'z'*(2**20));f=open(p,'r+b',buffering=0)
  for block in range(10):
   jobs=[]
   for alg,prefix in [(1,'ecdsa'),(2,'mldsa'),(3,'slhdsa')]:
    key=Key(alg);msg=b'A'*(164 if alg==3 else 132);sig=key.sign(msg)
    for op in ('keygen','sign','verify'):
     reps=8 if alg==3 else 400
     def task(alg=alg,op=op,reps=reps,key=key,msg=msg,sig=sig):
      for _ in range(reps):
       if op=='keygen':k=Key(alg);k.close()
       elif op=='sign':key.sign(msg)
       else:assert verify(alg,key.public,msg,sig)
     jobs.append((prefix+'_'+op,{prefix+'_'+op:reps},task))
   for branch,name in ((0,'sha256'),(1,'sha384')):
    for length,reps in ((65,4000),(1033,2000),(3442,1000),(35829,250)):
     payload=b'x'*length
     def task(branch=branch,payload=payload,reps=reps):
      m=Meter()
      for _ in range(reps):m.digest(branch,payload)
     jobs.append((f'{name}_{length}',{name+'_calls':reps,name+'_bytes':reps*length},task))
   for length in (1024,8192,65536):
    obj={'id':1,'padding':'x'*(length-21)};body=canonical(obj);length=len(body);reps=400 if length<10000 else 80
    def enc(obj=obj,reps=reps):
     for _ in range(reps):canonical(obj)
    jobs.append((f'encode_{length}',{'encode_objects':reps,'encode_bytes':reps*length},enc))
    frame=pack_frame(1,1,body)
    def dec(frame=frame,reps=reps):
     m=Meter()
     for _ in range(reps):
      t,oid,b=decode_frame(frame[:16],frame[16:],m);json.loads(b,object_pairs_hook=dict)
    jobs.append((f'decode_json_{length}',{'decode_objects':reps,'decode_bytes':reps*len(frame)},dec))
   for length in (196,3441,35828):
    frame=pack_frame(3,1,b'x'*length);reps=1000
    def decbin(frame=frame,reps=reps):
     m=Meter()
     for _ in range(reps):decode_frame(frame[:16],frame[16:],m)
    jobs.append((f'decode_binary_{length}',{'decode_objects':reps,'decode_bytes':reps*len(frame)},decbin))
   for length,reps in ((16,4000),(1024,2000),(32768,200),(131072,50)):
    payload=b'r'*length
    def rd(length=length,reps=reps):
     f.seek(0);m=Meter()
     # These repeated read calls remain in the 1 MiB warm working set.
     for i in range(reps):
      if i*length%(2**20)==0:f.seek(0)
      m.read(f,length)
    def wr(payload=payload,reps=reps):
     f.seek(0)
     for _ in range(reps):f.write(payload)
    jobs.append((f'read_{length}',{'read_calls':reps,'read_bytes':reps*length},rd))
    jobs.append((f'write_{length}',{'write_calls':reps,'write_bytes':reps*length},wr))
   def barriers():
    for _ in range(8):os.fsync(f.fileno())
   jobs.append(('barrier_empty_warm',{'barrier_calls':8},barriers))
   def visits():
    for i in range(100000):visit(i)
   jobs.append(('subject_visit',{'subject_visits':100000},visits))
   rng.shuffle(jobs)
   for name,counts,fn in jobs:measure(block,name,counts,fn)
   print('calibration block',block,'complete',flush=True)
  f.close()
 write_json(ROOT/'measured/calibration.json',{'phase':'calibration','evidence_type':'measured','features':FEATURES,'rows':rows,'warmup_rule':'One identical untimed invocation immediately before each measurement','barrier_note':'Warm empty fsync component, not physical durability; coefficient inactive in verification target','design_scope':'Independent primitive and serialization microbenchmarks; not a whole-query fit'})
 print(fit_command(ROOT/'measured/calibration.json',ROOT/'release/coefficients.json'))
if __name__=='__main__':run()
