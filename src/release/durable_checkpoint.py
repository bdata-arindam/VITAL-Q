"""Synchronous post-history save; never overlaps a measurement worker."""
from pathlib import Path
import os,json,sys,hashlib,zipfile,subprocess,time,shutil
ROOT=Path(__file__).resolve().parent.parent
EXPORT=Path(os.environ['VITAL_Q_CHECKPOINT_EXPORT'])
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.hexdigest()
def upload(path,identity=None):
 request={'local_path':str(path.resolve()),'purpose':'replace_library_file' if identity else 'create_library_file'}
 if identity:request.update(library_file_id=identity['library_file_id'],expected_current_version=identity['current_version_number'],version_reason='Verified completed-history checkpoint')
 out=subprocess.run([sys.executable,str(EXPORT/'checkpoint_helpers/library_upload.py')],input=json.dumps({'uploads':[request]}),text=True,capture_output=True,check=True)
 lines=[json.loads(s) for s in out.stdout.splitlines() if s.startswith('{"results":')]
 if not lines:raise RuntimeError('No upload result: '+out.stderr[-500:])
 result=lines[-1]['results'][0]
 if result['status']!='succeeded':raise RuntimeError(json.dumps(result))
 return result

def save():
 status=ROOT/'audit/checkpoint_latest_receipt.json'
 identity=json.loads(status.read_text())['upload'] if status.exists() else None
 files={}
 for folder in ['release','audit','measured','retained','native','results','documents','figures','logs']:
  if not (ROOT/folder).exists():continue
  for p in (ROOT/folder).rglob('*'):
   if p.is_file() and '__pycache__' not in p.parts:files['revision/'+p.relative_to(ROOT).as_posix()]=p
 for p in EXPORT.glob('*.py'):files[p.name]=p
 for p in (EXPORT/'checkpoint_helpers').glob('*.py'):files['checkpoint_helpers/'+p.name]=p
 for p in (EXPORT/'deliverables').glob('VITAL_Q_Pre_Evaluation_Protocol*.zip'):files['deliverables/'+p.name]=p
 notebook=ROOT/'VITAL_Q_Analysis_Executed.ipynb'
 if notebook.exists():files['revision/'+notebook.name]=notebook
 captured={n:p.read_bytes() for n,p in files.items()}
 manifest={'files':{n:{'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for n,data in captured.items()},'created_unix':time.time()}
 target=EXPORT/'deliverables/VITAL_Q_Full_Run_Checkpoint.zip';target.parent.mkdir(exist_ok=True)
 with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=3) as z:
  for n,data in captured.items():z.writestr(n,data)
  z.writestr('PACKAGE_MANIFEST.json',json.dumps(manifest,indent=2))
 with zipfile.ZipFile(target) as z:
  if z.testzip() is not None:raise RuntimeError('Checkpoint CRC failure')
  for n,rec in manifest['files'].items():
   if hashlib.sha256(z.read(n)).hexdigest()!=rec['sha256']:raise RuntimeError('Checkpoint hash mismatch: '+n)
 history=ROOT/'measured/histories.jsonl'
 rows=[json.loads(s) for s in history.read_text().splitlines()] if history.exists() else []
 result=upload(target,identity)
 receipt={'saved_unix':time.time(),'checkpoint_sha256':digest(target),'successful_development_histories':sum(r['phase']=='development' and r['status']=='ok' for r in rows),'successful_evaluation_histories':sum(r['phase']=='evaluation' and r['status']=='ok' for r in rows),'upload':result}
 status.write_text(json.dumps(receipt,indent=2)+'\n')
 (EXPORT/'checkpoint_latest_receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
 # Update reviewable workspace copies only while all measurement workers are stopped.
 for folder in ['audit','measured','retained','results','documents','figures']:
  if (ROOT/folder).exists():shutil.copytree(ROOT/folder,EXPORT/'revision'/folder,dirs_exist_ok=True)
 print(json.dumps({'checkpoint_saved':True,'development_histories':receipt['successful_development_histories'],'evaluation_histories':receipt['successful_evaluation_histories'],'version':result['current_version_number']}),flush=True)
 return receipt
if __name__=='__main__':save()
