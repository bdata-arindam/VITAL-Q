"""New collections require a fresh directory and a pre-evaluation snapshot.

The delivered notebook replays analysis only. For a new collection, copy the
release and native folders to a new root, create audit/measured/results/work/
retained/logs directories, remove models.json and training_input_hashes.json,
and regenerate the schedule with fresh block identifiers before development.
Never mix new data with delivered rows. Native-library paths are configured by
OQS_INSTALL_PATH; no auto download is performed by this runner.
"""
import argparse,subprocess,sys,os,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
def main():
    p=argparse.ArgumentParser()
    p.add_argument('action',choices=['development','freeze','evaluation','analyze','validate'])
    a=p.parse_args()
    if a.action=='development':
        if (ROOT/'measured/development.jsonl').exists():raise SystemExit('Development already exists; use a fresh study directory')
        jobs=[('test_timing.py',[]),('qualification.py',[]),('calibration.py',[]),('campaign.py',['development'])]
    elif a.action=='freeze':jobs=[('analysis_v4.py',['freeze'])]
    elif a.action=='evaluation':jobs=[('campaign.py',['evaluation'])]
    elif a.action=='analyze':jobs=[('analysis_v4.py',['analyze'])]
    else:jobs=[('validate_results.py',[])]
    for name,args in jobs:
        subprocess.run([sys.executable,str(ROOT/'release'/name),*args],check=True,
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1'))
if __name__=='__main__':main()
