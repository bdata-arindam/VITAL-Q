"""Audit complete blocks, protocol balance, time ordering and public evidence."""
import json,sys,collections
from pathlib import Path
from research_tools import verify_freeze,sha,ledger
from verifier import verify_proof
ROOT=Path(__file__).resolve().parent.parent

def run():
    verify_freeze(ROOT/'release',ROOT/'audit/freeze.json')
    observations=[json.loads(x) for x in (ROOT/'measured/evaluation.jsonl').read_text().splitlines()]
    histories=[json.loads(x) for x in (ROOT/'measured/histories.jsonl').read_text().splitlines()]
    scheduled=json.loads((ROOT/'release/schedule.json').read_text())['histories']
    assert len(observations)==1080 and len(histories)==162
    assert {r['history_id'] for r in histories}=={r['history_id'] for r in scheduled}
    assert all(r['status']=='ok' for r in histories)
    freeze=json.loads((ROOT/'audit/freeze_receipt.json').read_text())
    receipt=json.loads((ROOT/'audit/external_snapshot_receipt.json').read_text())
    ev=[r for r in histories if r['phase']=='evaluation'];dev=[r for r in histories if r['phase']=='development']
    assert max(r['finished_unix'] for r in dev)<freeze['local_time_unix']<min(r['started_unix'] for r in ev)
    assert receipt['saved_before_evaluation'] and receipt['receipt_recorded_unix']<min(r['started_unix'] for r in ev)
    balance={}
    for arm in 'NED':
        rows=[r for r in observations if r['arm']==arm and r['mode']=='balanced']
        position=collections.Counter((r['renewals'],r['query'],r['position']) for r in rows)
        pairs=collections.Counter((tuple(r['predecessor']),r['renewals'],r['query']) for r in rows if r['predecessor'] is not None)
        assert len(position)==36 and set(position.values())=={5}
        assert len(pairs)==30 and set(pairs.values())=={5}
        assert collections.Counter(r['mode_position'] for r in rows)=={0:90,1:90}
        balance[arm]={'task_position_cells':36,'observations_each':5,'ordered_predecessor_pairs':30,'pairs_each':5,'mode_first_second':[90,90]}
    proof_checks=0
    for h in histories:
        assert h['archive_bytes']==ledger(h['n'],6)['archive_bytes'][h['arm']]
        d=ROOT/'retained'/h['history_id'];policy=json.loads((d/'policy.json').read_text())
        for g in (0,2,5):
            p=d/f'selective-R{g}.pqp'
            accepted=verify_proof(p,policy,expected=(g,'selective',h['query_id']))
            assert accepted['accepted'];proof_checks+=1
            if h['phase']=='evaluation':
                match=[r for r in observations if r['history_id']==h['history_id'] and r['renewals']==g and r['query']=='selective']
                assert len(match)==2 and all(r['proof_sha256']==sha(p) and r['counts']==accepted['counts'] for r in match)
    out={'release_unchanged':True,'timing_order_checks_passed':True,'evaluation_observations':len(observations),
        'successful_histories':len(histories),'public_selective_proofs_reverified':proof_checks,
        'archive_ledgers_reconciled':len(histories),'balance':balance,
        'external_snapshot_is_public_preregistration':False,'external_snapshot_is_trusted_timestamp':False,
        'complete_full_archives_retained':False,'scope':'Code and data consistency audit by executing assistant, not independent human review'}
    (ROOT/'audit/final_validation.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(out,indent=2))

if __name__=='__main__':run()
