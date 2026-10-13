"""Model forms and fitting fixed before the new development campaign."""
import numpy as np
from scipy.optimize import nnls
from research_tools import FEATURES
AFFINE=['intercept','validated_records','ecdsa_tokens','mldsa_tokens','slhdsa_tokens','enrollment_objects','merkle_internal_hashes']
MODELS={
    'validation_affine':AFFINE,
    'without_intercept':AFFINE[1:],
    'without_record_validation':[f for f in AFFINE if f!='validated_records'],
    'bytes_only':['proof_bytes'],
    'affine_bytes':['intercept','proof_bytes'],
    'tokens_plus_bytes':['intercept','all_tokens','proof_bytes'],
}
def features(row):
    counts=dict(zip(FEATURES,row['counts']))
    m=row['n'] if row['query']=='full' else 1
    k=(row['n']+4095)//4096
    if row['arm']=='N':nodes=0
    elif row['query']=='full':nodes=(row['n']-k)*(2 if row['arm']=='D' else 1)
    else:
        from research_tools import path_length
        nodes=path_length(min(4096,row['n']-(row['query_id']//4096)*4096),row['query_id']%4096)*(2 if row['arm']=='D' else 1)
    tokens=[counts[a+'_verify'] for a in ('ecdsa','mldsa','slhdsa')]
    return dict(zip(AFFINE,[1,m,*tokens,(row['renewals']+1)*(2 if row['arm']=='D' else 1),nodes]),
        proof_bytes=row['proof_bytes'],all_tokens=sum(tokens))
def matrix(rows,columns):return np.asarray([[features(r)[f] for f in columns] for r in rows],float)
def fit(rows,columns):
    # Same development cells, medians and relative-error weighting for every model.
    groups={}
    for r in rows:
        key=(r['n'],r['arm'],r['query'],r['renewals'])
        groups.setdefault(key,[]).append(r)
    x=[];y=[]
    for key,group in sorted(groups.items()):
        x.append(np.median(matrix(group,columns),axis=0));y.append(np.median([r['seconds'] for r in group]))
    x=np.asarray(x);y=np.asarray(y);weighted=x/y[:,None];scale=np.linalg.norm(weighted,axis=0)
    if (scale==0).any():raise ValueError('Unused feature')
    norm=weighted/scale;rank=int(np.linalg.matrix_rank(norm))
    if rank<len(columns):raise ValueError('Rank deficient model')
    coef,res=nnls(norm,np.ones(len(y)))
    return {'columns':columns,'coefficients':(coef/scale).tolist(),'rank':rank,
        'condition_number':float(np.linalg.cond(norm)),'relative_fit_residual_l2':float(res),
        'training_cells':len(y),'training_rows':len(rows),'training_mode':'balanced',
        'fit':'NNLS of cell medians with inverse median latency weights; no evaluation input'}
def predict(rows,model):return matrix(rows,model['columns'])@np.asarray(model['coefficients'])
