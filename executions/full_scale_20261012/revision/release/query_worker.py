"""Persistent process or one-shot process with identical crypto priming."""
import json,sys,os,time,gc,contextlib
from pathlib import Path
with contextlib.redirect_stdout(sys.stderr):
    from archive_builder import warm_file
    from crypto_backend import verify
    from verifier import verify_proof
from timing import checked_measure
ROOT=Path(__file__).resolve().parent.parent

def prime():
    for row in json.loads((ROOT/'release/crypto_primer.json').read_text()):
        assert verify(row['alg'], bytes.fromhex(row['public']),
                      bytes.fromhex(row['message']), bytes.fromhex(row['signature']))

def run(request):
    policy=json.loads(Path(request['policy_path']).read_text())
    # Prime file cache and dispose warmup allocations before starting the clock.
    warm_file(request['proof_path'])
    gc.collect()
    result=checked_measure(verify_proof, request['proof_path'], policy,
                           expected=tuple(request['expected']),
                           expected_counts=request['counts'])
    result.update(pid=os.getpid(), observed_unix=time.time())
    return result

if __name__=='__main__':
    prime()
    for line in sys.stdin:
        print(json.dumps(run(json.loads(line))),flush=True)
        if '--once' in sys.argv: break
