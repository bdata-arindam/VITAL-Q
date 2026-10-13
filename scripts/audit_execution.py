"""Read-only audit of the completed full-scale execution and its retained bytes."""
from pathlib import Path
import collections, csv, hashlib, json, math, zipfile

import sys
REPO = Path(__file__).resolve().parents[1]
RUN = Path(sys.argv[1]).resolve() if len(sys.argv)>1 else REPO/'executions/full_scale_20261012'
ROOT = RUN/'revision'
def read(p): return json.loads(p.read_text())
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def rows(p): return [json.loads(s) for s in p.read_text().splitlines()]

def main():
    assert read(RUN/'REPRODUCTION_STATUS.json')['status'] == 'passed'
    histories = rows(ROOT/'measured/histories.jsonl')
    schedule = read(ROOT/'release/schedule.json')['histories']
    assert len(histories) == 162
    assert {h['history_id'] for h in histories} == {h['history_id'] for h in schedule}
    assert all(h['status'] == 'ok' and h['condition_observations'] == 12 for h in histories)
    counts = {}
    expected = {(g,q,m) for g in (0,2,5) for q in ('full','selective') for m in ('balanced','isolated')}
    for phase, total, nh in [('development',864,72),('evaluation',1080,90)]:
        observations = rows(ROOT/f'measured/{phase}.jsonl')
        assert len(observations) == total
        grouped = collections.defaultdict(list)
        for r in observations:
            assert r['status']=='ok' and r['bytes_match'] and r['observed_counts_match']
            assert math.isfinite(r['seconds']) and r['seconds']>0
            grouped[r['history_id']].append(r)
        assert len(grouped)==nh
        for hid, actual in grouped.items():
            assert len(actual)==12 and {(r['renewals'],r['query'],r['mode']) for r in actual}==expected
            journal = read(ROOT/f'measured/per_history/{phase}/{hid}.json')
            canonical = json.dumps(journal['observations'],sort_keys=True,separators=(',',':')).encode()
            assert hashlib.sha256(canonical).hexdigest()==journal['sha256']
            assert journal['observations']==actual
        counts[phase]={'histories':nh,'observations':total,'sizes':sorted({r['n'] for r in observations})}
    assert counts['development']['sizes']==[1000,10000] and counts['evaluation']['sizes']==[100000]
    reference = read(REPO/'REFERENCE_SHA256.json')
    assert all(sha(REPO/p)==digest for p,digest in reference.items())
    training = read(ROOT/'release/training_input_hashes.json')
    assert all(sha(ROOT/p)==digest for p,digest in training.items())
    receipt=read(ROOT/'audit/freeze_receipt.json')
    assert max(h['finished_unix'] for h in histories if h['phase']=='development')<=receipt['local_time_unix']
    assert receipt['local_time_unix']<min(h['started_unix'] for h in histories if h['phase']=='evaluation')
    checkpoint=RUN/'checkpoints/latest.zip'
    assert sha(checkpoint)==read(ROOT/'audit/local_checkpoint.json')['sha256']
    with zipfile.ZipFile(checkpoint) as z:
        assert z.testzip() is None
        manifest=json.loads(z.read('CHECKPOINT_SHA256.json'))
        assert all(hashlib.sha256(z.read(p)).hexdigest()==digest for p,digest in manifest.items())
        # The receipt itself is updated after the ZIP has been committed.
        assert all(sha(ROOT/p)==digest for p,digest in manifest.items() if p!='audit/local_checkpoint.json')
    qualification=read(ROOT/'audit/qualification.json')
    assert qualification['passed']==qualification['total']==233
    analysis=read(ROOT/'results/analysis.json')
    published=read(REPO/'data/published/results/analysis.json')
    with (ROOT/'results/model_cells.csv').open() as f: cells=list(csv.DictReader(f))
    assert len(cells)==252
    for r in cells:
        matching=[c for c in analysis[r['mode']]['100000']['models'][r['model']]['cells'] if c['arm']==r['arm'] and c['query']==r['query'] and c['renewals']==int(r['renewals'])]
        assert len(matching)==1
        for key in ('relative_error','observed_median_seconds','predicted_median_seconds'):
            assert float(r[key])==matching[0][key]
    metrics={}
    for mode in ('balanced','isolated'):
        a=analysis[mode]['100000']; p=published[mode]['100000']
        metrics[mode]={
            'fresh_median_absolute_relative_error_percent':100*a['models']['validation_affine']['median_absolute_relative_error'],
            'published_median_absolute_relative_error_percent':100*p['models']['validation_affine']['median_absolute_relative_error'],
            'fresh_bytes_only_error_percent':100*a['models']['bytes_only']['median_absolute_relative_error'],
            'fresh_point_passes':a['models']['validation_affine']['point_passes'],
            'fresh_interval_passes':a['models']['validation_affine']['interval_passes'],
            'fresh_support_rule_passed':a['support_rule_passed']}
    result={'status':'passed','counts':counts,'qualification_passed':233,
        'final_verification':read(ROOT/'audit/final_validation.json'),
        'reference_files_unchanged':len(reference),'journal_histories_validated':162,
        'checkpoint_members_validated':len(manifest),'checkpoint_sha256':sha(checkpoint),
        'model_cells_csv_rows':len(cells),'training_input_hashes_match':True,
        'local_freeze_precedes_evaluation':True,'metrics':metrics,
        'environment':read(ROOT/'release/environment.json'),
        'execution_started_unix':read(ROOT/'audit/PORTABILITY_AMENDMENT.json')['created_unix'],
        'last_history_finished_unix':max(h['finished_unix'] for h in histories),
        'scope':'Fresh full-scale execution in this environment; not external independent replication. Published measurements and manuscript unchanged.'}
    (RUN/'FULL_SCALE_AUDIT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
if __name__=='__main__': main()
