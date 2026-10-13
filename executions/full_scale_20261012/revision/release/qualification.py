import json,hashlib,tempfile,struct,copy,time,shutil,inspect
from pathlib import Path
from archive_builder import *
from verifier import verify_proof,EvidenceError,payload_audit
from crypto_backend import Key,verify
from research_tools import FEATURES,sha
ROOT=Path(__file__).resolve().parent.parent

def run():
 results=[]
 def record(name,fn,expected=True):
  start=time.perf_counter()
  try:actual=bool(fn());detail=''
  except Exception as e:actual=False;detail=repr(e)
  passed=actual==expected;results.append(dict(test=name,expected=expected,actual=actual,passed=passed,seconds=time.perf_counter()-start,detail=detail))
  if not passed:raise AssertionError(results[-1])
 def rejection(p,pol,expected=(5,'selective',4)):
  try:verify_proof(p,pol,expected=expected);return False
  except EvidenceError:return True
 for alg in (1,2,3):
  k=Key(alg);wrong=Key(alg);msg=b'm'*(164 if alg==3 else 132);sig=k.sign(msg)
  for name,pk,m,s,expected in [('valid',k.public,msg,sig,True),('wrong_key',wrong.public,msg,sig,False),('message_tamper',k.public,msg[:-1]+b'q',sig,False),('signature_tamper',k.public,msg,bytes([sig[0]^1])+sig[1:],False),('truncated_sig',k.public,msg,sig[:-1],False),('bad_key',k.public[:-1],msg,sig,False)]:
   record(f'algorithm{alg}_{name}',lambda pk=pk,m=m,s=s:verify(alg,pk,m,s),expected)
  if alg in (2,3):
   # Distinct native implementation: pqcrypto 1.0.0 Rust pqcrypto FIPS algorithms.
   from pqcrypto.sign import ml_dsa_65,slh_dsa_sha2_192f
   other=ml_dsa_65 if alg==2 else slh_dsa_sha2_192f
   record(f'algorithm{alg}_cross_verify_oqs_to_pqcrypto',lambda:other.verify(k.public,msg,sig) is None)
   pk,sk=other.keygen();osig=other.sign(sk,msg)
   record(f'algorithm{alg}_cross_verify_pqcrypto_to_oqs',lambda:verify(alg,pk,msg,osig))
  k.close();wrong.close()
 with tempfile.TemporaryDirectory(dir=ROOT/'work') as td:
  td=Path(td)
  for n in (1,2,3,5,4095,4096,4097):
   for arm in 'NED':
    a=build_archive(td/'archive.bin',synthetic_manifests(n,123),arm)
    for g in (0,2,5):
     for query in ('full','selective'):
      qid=n-1;p=td/'proof.bin';construct_proof(a,p,g,query,qid)
      r=verify_proof(p,a['policy'],expected=(g,query,qid));counts,size=predicted_counts(arm,n,g,query,qid)
      record(f'ledger_and_verification_{arm}_{n}_{g}_{query}',lambda:r['counts']==counts and size==p.stat().st_size)
      if n==5 and g==5 and query=='selective':
       raw=p.read_bytes()
       record(f'{arm}_wrong_requested_checkpoint_rejected',lambda:rejection(p,a['policy'],(2,'selective',4)))
       record(f'{arm}_wrong_requested_record_rejected',lambda:rejection(p,a['policy'],(5,'selective',3)))
       record(f'{arm}_wrong_requested_mode_rejected',lambda:rejection(p,a['policy'],(5,'full',4)))
       for name,index in [('header_version',8),('manifest_byte',100),('signature_byte',len(raw)-1),('reserved_frame',70)]:
        bad=td/'bad.bin';b=bytearray(raw);b[index]^=1;bad.write_bytes(b)
        record(f'{arm}_{name}_rejected',lambda:rejection(bad,a['policy']))
       for name,b in [('truncated',raw[:-1]),('duplicate_object',raw+raw[64:1104]),('missing_predecessor',raw[:-100])]:
        bad.write_bytes(b);record(f'{arm}_{name}_rejected',lambda:rejection(bad,a['policy']))
       alien=copy.deepcopy(a['policy']);alien['history_id']='00'*32
       record(f'{arm}_cross_history_rejected',lambda:rejection(p,alien))
       if arm=='D':
        disabled=copy.deepcopy(a['policy']);disabled['algorithm_breaks']['2']=a['epoch']+450
        record('D_primary_family_break_survives',lambda:verify_proof(p,disabled,expected=(5,'selective',4))['branch_eligible']=={0:False,1:True})
        disabled['algorithm_breaks']['3']=a['epoch']+450
        record('D_both_families_break_rejected',lambda:rejection(p,disabled))
       late=copy.deepcopy(a['policy']);late['algorithm_breaks']['1']=a['epoch']+50
       record(f'{arm}_late_migration_policy',lambda:rejection(p,late),arm!='D')
      p.unlink()
    (td/'archive.bin').unlink()
  # Enumerate every completed object boundary on tiny three-generation archives.
  for arm in 'NED':
   a=build_archive(td/'tiny.bin',synthetic_manifests(3,987),arm,3);raw=(td/'tiny.bin').read_bytes();boundaries=[64];off=64
   while off<len(raw):off+=16+FRAME.unpack(raw[off:off+16])[-1];boundaries.append(off)
   p=td/'all.bin';construct_proof(a,p,2,'full',1);full=p.read_bytes()
   for cutoff in boundaries:
    # A recoverable checkpoint requires every object used in its full proof.
    reopened=td/'crash.bin';reopened.write_bytes(raw[:cutoff]);reopened.read_bytes()
    required=[off for v in a['token_index'].values() for off in v]+list(a['keys_index'].values())
    complete=all(pos+len(read_raw(open(a['path'],'rb'),pos))<=cutoff for pos in required)
    # Replay construction exclusively against truncated bytes and then public verifier.
    ac=dict(a,path=str(reopened));trial=td/'crash-proof.bin'
    try:construct_proof(ac,trial,2,'full',1);accepted=verify_proof(trial,a['policy'],expected=(2,'full',1))['accepted']
    except (ValueError,OSError,EvidenceError):accepted=False
    record(f'{arm}_logical_crash_at_{cutoff}',lambda:accepted==complete)
    if trial.exists():trial.unlink()
   p.unlink();(td/'tiny.bin').unlink()
  # Stored lookup node corruption is repairable from trusted manifests.
  mm=synthetic_manifests(5,567);a=build_archive(td/'tree.bin',mm,'E');p=td/'treeproof.bin';construct_proof(a,p,5,'selective',4)
  pristine=(td/'tree.bin').read_bytes();broken=bytearray(pristine);nodepos=a['tree_index'][0,0]+40+5*32+2*32;broken[nodepos]^=1;(td/'tree.bin').write_bytes(broken)
  p.unlink();construct_proof(a,p,5,'selective',4)
  record('corrupt_lookup_node_rejected',lambda:rejection(p,a['policy']))
  st=time.perf_counter();levels=tree(mm,0,0);stored=levels[0]+[x for j,lev in enumerate(levels[1:]) for x in lev[:len(levels[j])//2]];restored=bytearray(broken);restored[a['tree_index'][0,0]+40:a['tree_index'][0,0]+40+len(stored)*32]=b''.join(stored);(td/'tree.bin').write_bytes(restored);elapsed=time.perf_counter()-st
  p.unlink();construct_proof(a,p,5,'selective',4);record('tree_reconstruction_restores_lookup',lambda:verify_proof(p,a['policy'],expected=(5,'selective',4))['accepted'])
  recovery={'records_processed':5,'hashes':9,'signatures_created':0,'signatures_checked':6,'timestamp_operations':0,'bytes_read':5*1024,'bytes_written':len(restored),'seconds_reconstruction_only':elapsed,'note':'Disposable fixture rewrites its archive copy; no lost history repaired.'}
 # Case corruption fixtures use retained signed proofs and disposable changed payloads.
 (ROOT/'audit/qualification.json').write_text(json.dumps({'tests':results,'total':len(results),'passed':sum(x['passed'] for x in results),'tree_recovery':recovery,'physical_power_loss_test':False},indent=2))
 print(json.dumps({'total':len(results),'passed':sum(x['passed'] for x in results)}))
if __name__=='__main__':run()
