"""Read-only numerical replay and frozen-release checks; no benchmark collection.
Run from any directory with NumPy and SciPy available. Writes JSON only when
--output is supplied. Does not call the hosted checkpoint service.
"""
from pathlib import Path
import argparse,collections,hashlib,json,sys,subprocess,os
ROOT=Path(__file__).resolve().parents[1]
R=ROOT/'revision'
sys.dont_write_bytecode=True
sys.path.insert(0,str(R/'release'))
import numpy as np
from model import fit,MODELS
from analysis_v4 import summaries

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rows(name):return [json.loads(x) for x in (R/'measured'/f'{name}.jsonl').read_text().splitlines()]
def run():
 frozen=json.loads((R/'audit/freeze.json').read_text())['files']
 errors=[n for n,h in frozen.items() if not (R/'release'/n).exists() or sha(R/'release'/n)!=h]
 assert not errors,errors
 dev,ev,hist=rows('development'),rows('evaluation'),rows('histories')
 assert (len(dev),len(ev),len(hist))==(864,1080,162)
 assert all(x['status']=='ok' for x in dev+ev+hist)
 assert collections.Counter(x['phase'] for x in hist)=={'development':72,'evaluation':90}
 models=json.loads((R/'release/models.json').read_text());fit_model=fit([x for x in dev if x['mode']=='balanced'],MODELS['validation_affine'])
 assert np.allclose(fit_model['coefficients'],models['validation_affine']['coefficients'],rtol=1e-10,atol=1e-14)
 actual=summaries(ev,models,bootstrap=True);saved=json.loads((R/'results/analysis.json').read_text())
 # Check every scalar/list in the replayed model summaries against the supplied analysis.
 numeric_checks=0
 def compare(a,b,path=''):
  nonlocal numeric_checks
  if isinstance(a,dict):
   for k,v in a.items():compare(v,b[k],path+'/'+k)
  elif isinstance(a,list):
   assert len(a)==len(b),path
   for i,(v,w) in enumerate(zip(a,b)):compare(v,w,path+f'/{i}')
  elif isinstance(a,(float,int)) and not isinstance(a,bool):
   assert np.isclose(a,b,rtol=1e-10,atol=1e-12),(path,a,b);numeric_checks+=1
  else:assert a==b,(path,a,b)
 for mode in ['balanced','isolated']:compare(actual[mode],saved[mode],mode)
 q=json.loads((R/'audit/qualification.json').read_text())['tests']
 assert len(q)==233 and all(x['passed'] for x in q)
 proofs=list((R/'retained').rglob('*.pqp'));assert len(proofs)==486
 env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1'
 proc=subprocess.run([sys.executable,str(R/'release/test_timing.py')],cwd=R/'release',env=env,capture_output=True,text=True)
 assert proc.returncode==0,proc.stdout+proc.stderr
 result={'scope':'Numerical reanalysis of supplied measurements and timing unit tests; no fresh benchmark or independent external replication',
 'frozen_release_files_checked':len(frozen),'frozen_release_hashes_match':True,'development_observations':len(dev),'evaluation_observations':len(ev),'histories':len(hist),
 'coefficient_refit_matches':True,'training_rows':fit_model['training_rows'],'training_cells':fit_model['training_cells'],
 'bootstrap_draws':10000,'replayed_numeric_fields_matching_saved_analysis':numeric_checks,'retained_selective_proof_files':len(proofs),
 'qualification_record':{'recorded_passes':233,'cryptographic_qualification_rerun_in_this_check':False},
 'timer_tests':{'rerun':True,'passed':2,'output':proc.stdout+proc.stderr},
 'python':sys.version.split()[0],'numpy':np.__version__,
 'inputs_sha256':{str(p.relative_to(ROOT)):sha(p) for p in [R/'measured/development.jsonl',R/'measured/evaluation.jsonl',R/'release/models.json',R/'results/analysis.json']},
 'results':{m:{'corrected_mare_percent':100*actual[m]['100000']['models']['validation_affine']['median_absolute_relative_error'],
 'corrected_passes':actual[m]['100000']['models']['validation_affine']['point_passes'],
 'bytes_only_mare_percent':100*actual[m]['100000']['models']['bytes_only']['median_absolute_relative_error']} for m in ['balanced','isolated']}}
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args();r=run();s=json.dumps(r,indent=2)+'\n'
 if a.output:a.output.write_text(s)
 print(s)
