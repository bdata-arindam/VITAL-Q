"""Predeclared fitting, freezing and complete-grid analysis for version 4."""
import json,time,sys,csv,hashlib,zipfile,itertools
from pathlib import Path
import numpy as np
from model import MODELS,fit,predict
from research_tools import CELLS,FEATURES,freeze,verify_freeze,sha
ROOT=Path(__file__).resolve().parent.parent

def read_rows(name):return [json.loads(line) for line in (ROOT/'measured'/f'{name}.jsonl').read_text().splitlines()]
def write(path,obj):
    if path.exists():raise FileExistsError(path)
    path.write_text(json.dumps(obj,indent=2)+'\n')

def fit_and_freeze():
    dev=read_rows('development')
    assert len(dev)==864 and all(r['status']=='ok' for r in dev)
    rows=[r for r in dev if r['mode']=='balanced']
    models={name:fit(rows,cols) for name,cols in MODELS.items()}
    write(ROOT/'release/models.json',models)
    write(ROOT/'audit/development_summary.json',summaries(dev,models,bootstrap=False))
    sources={str(p.relative_to(ROOT)):sha(p) for p in [ROOT/'measured/development.jsonl',ROOT/'measured/calibration.json',ROOT/'audit/qualification.json']}
    write(ROOT/'release/training_input_hashes.json',sources)
    freeze(ROOT/'release',ROOT/'audit/freeze.json')
    write(ROOT/'audit/freeze_receipt.json',{'local_time_unix':time.time(),'release_manifest_sha256':sha(ROOT/'audit/freeze.json'),
        'human_review':'Arindam Chakraborty named as reviewer by author; original review date and scope unspecified; no pre-evaluation human approval claimed for version 4',
        'trust':'Local clock; separate hosted snapshot receipt required before evaluation',
        'prior_results_known':True,'evaluation_size_previously_exercised':True})
    target=ROOT.parent/'deliverables/VITAL_Q_Pre_Evaluation_Protocol.zip'
    target.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(target,'x',compression=zipfile.ZIP_DEFLATED) as z:
        for folder in ('release','audit','measured'):
            for p in sorted((ROOT/folder).rglob('*')):
                if p.is_file():z.write(p,p.relative_to(ROOT))
    print(json.dumps({'snapshot':str(target),'sha256':sha(target),'models':models},indent=2))

def summaries(observations,models,bootstrap=True):
    output={}
    micro=np.asarray(json.loads((ROOT/'release/coefficients.json').read_text())['coefficients_seconds'])
    for mode in ('balanced','isolated'):
        rows=sorted([r for r in observations if r['mode']==mode],key=lambda r:(r['n'],r['block_id'],r['arm'],r['query'],r['renewals']))
        sizes=sorted({r['n'] for r in rows})
        bysize={}
        for n in sizes:
            subset=[r for r in rows if r['n']==n];blocks=sorted({r['block_id'] for r in subset})
            lookup={(r['block_id'],r['arm'],r['query'],r['renewals']):r for r in subset}
            assert len(lookup)==len(blocks)*18
            ordered=[[lookup[(b,*cell)] for b in blocks] for cell in CELLS]
            actual=np.asarray([[r['seconds'] for r in group] for group in ordered])
            preds={name:np.asarray([predict(group,model) for group in ordered]) for name,model in models.items()}
            preds['micro_components']=np.asarray([[np.dot(r['counts'],micro) for r in group] for group in ordered])
            if bootstrap:
                rng=np.random.default_rng(2192026)
                ix=rng.integers(0,len(blocks),size=(10000,len(blocks)))
                med_actual=np.median(actual[:,ix],axis=2)
            results={};error_draws={}
            for name,pred in preds.items():
                a=np.median(actual,axis=1);p=np.median(pred,axis=1);err=(p-a)/a
                if bootstrap:
                    draws=(np.median(pred[:,ix],axis=2)-med_actual)/med_actual
                    error_draws[name]=draws
                cells=[]
                for j,cell in enumerate(CELLS):
                    d={'arm':cell[0],'query':cell[1],'renewals':cell[2],'n':n,'histories':len(blocks),
                        'observed_median_seconds':float(a[j]),'predicted_median_seconds':float(p[j]),
                        'relative_error':float(err[j]),'point_pass':bool(abs(err[j])<=.15)}
                    if bootstrap:
                        ci=np.percentile(draws[j],[2.5,97.5]).tolist()
                        d.update(error_interval_95=ci,interval_pass=bool(ci[0]>=-.15 and ci[1]<=.15))
                    cells.append(d)
                results[name]={'cells':cells,'point_passes':int((np.abs(err)<=.15).sum()),
                    'median_absolute_relative_error':float(np.median(np.abs(err))),
                    'max_absolute_relative_error':float(np.max(np.abs(err))),
                    'negative_errors':int((err<0).sum()),
                    'every_stratum_has_pass':all(any(d['point_pass'] for d in cells if d['arm']==arm and d['query']==q) for arm in 'NED' for q in ('full','selective'))}
                if bootstrap:results[name]['interval_passes']=sum(d['interval_pass'] for d in cells)
            c=results['validation_affine'];b=results['bytes_only']
            support=c['point_passes']>=15 and c['every_stratum_has_pass'] and c['median_absolute_relative_error']<b['median_absolute_relative_error']
            entry={'models':results,'blocks':blocks,'support_rule_passed':support,
                   'conditional_on_frozen_fit':True,'pointwise_intervals':True}
            if bootstrap:
                diff=np.median(np.abs(error_draws['validation_affine']),axis=0)-np.median(np.abs(error_draws['bytes_only']),axis=0)
                entry['paired_median_absolute_error_difference']={'point':c['median_absolute_relative_error']-b['median_absolute_relative_error'],
                    'interval_95':np.percentile(diff,[2.5,97.5]).tolist(),
                    'unit':'relative error; multiply by 100 for percentage points; negative favors corrected model'}
            bysize[str(n)]=entry
        output[mode]=bysize
    return output

def analyze():
    verify_freeze(ROOT/'release',ROOT/'audit/freeze.json')
    rows=read_rows('evaluation');statuses=[s for s in read_rows('histories') if s['phase']=='evaluation']
    assert len(statuses)==90 and all(s['status']=='ok' for s in statuses)
    assert len(rows)==1080 and all(r['status']=='ok' and r['bytes_match'] and r['observed_counts_match'] for r in rows)
    models=json.loads((ROOT/'release/models.json').read_text())
    result=summaries(rows,models)
    result['collection']={'histories':90,'observations':1080,'matched_blocks':30,
        'start_unix':min(s['started_unix'] for s in statuses),'end_unix':max(s['finished_unix'] for s in statuses),
        'all_counts_and_bytes_match':True,'max_rss_bytes':max(s['max_rss_bytes'] for s in statuses),
        'release_unchanged':True,'raw_sha256':sha(ROOT/'measured/evaluation.jsonl')}
    # Paired mode comparison using the same matched-block resamples for all cells.
    modes={m:{(r['block_id'],r['arm'],r['query'],r['renewals']):r for r in rows if r['mode']==m} for m in ('balanced','isolated')}
    blocks=sorted({r['block_id'] for r in rows});rng=np.random.default_rng(2192026);ix=rng.integers(0,30,size=(10000,30));comparison=[]
    for cell in CELLS:
        b=np.asarray([modes['balanced'][(block,*cell)]['seconds'] for block in blocks]);i=np.asarray([modes['isolated'][(block,*cell)]['seconds'] for block in blocks])
        ratios=i/b;draws=np.median(ratios[ix],axis=1)
        comparison.append(dict(arm=cell[0],query=cell[1],renewals=cell[2],median_paired_ratio_isolated_to_balanced=float(np.median(ratios)),interval_95=np.percentile(draws,[2.5,97.5]).tolist()))
    result['mode_comparison']=comparison
    # Carryover summaries retain the planned predecessor and mode order.
    groups={}
    for r in rows:
        if r['mode']!='balanced':continue
        prev='first' if r['predecessor'] is None else r['predecessor'][1]
        groups.setdefault((r['arm'],r['query'],r['renewals'],prev),[]).append(r['seconds'])
    result['predecessor_summaries']=[dict(arm=k[0],query=k[1],renewals=k[2],predecessor=k[3],count=len(v),median_seconds=float(np.median(v))) for k,v in sorted(groups.items())]
    write(ROOT/'results/analysis.json',result)
    with (ROOT/'results/model_cells.csv').open('x',newline='') as f:
        flat=[]
        for mode in ('balanced','isolated'):
            for name,item in result[mode]['100000']['models'].items():
                flat.extend(dict(mode=mode,model=name,**c) for c in item['cells'])
        writer=csv.DictWriter(f,fieldnames=list(flat[0]));writer.writeheader();writer.writerows(flat)
    print(json.dumps({m:result[m]['100000']['models']['validation_affine'] for m in ('balanced','isolated')},indent=2))

if __name__=='__main__':
    if sys.argv[1]=='freeze':fit_and_freeze()
    elif sys.argv[1]=='analyze':analyze()
    else:raise ValueError('Expected freeze or analyze')
