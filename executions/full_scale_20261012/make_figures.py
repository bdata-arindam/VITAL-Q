from pathlib import Path
import json,numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
r=Path(__file__).resolve().parent/'revision';a=json.loads((r/'results/analysis.json').read_text())
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10.5,'axes.spines.top':False,'axes.spines.right':False})
fig,axes=plt.subplots(2,1,figsize=(9,7),sharex=True,constrained_layout=True)
for ax,mode in zip(axes,['balanced','isolated']):
 models=a[mode]['100000']['models'];x=np.arange(18)
 ax.axhspan(-15,15,color='#d7e9df',alpha=.65,label='15% tolerance')
 for offset,name,color,marker,label in [(-.16,'validation_affine','#1d537a','o','Validation-aware affine'),(0,'bytes_only','#ba6139','s','Bytes only'),(.16,'micro_components','#72777d','^','Primitive components')]:
  rows=models[name]['cells'];ax.plot(x+offset,[100*v['relative_error'] for v in rows],linestyle='none',marker=marker,color=color,markersize=4,label=label)
 ax.axhline(0,color='black',linewidth=.5);ax.set_ylabel('Signed relative error (%)');ax.set_title(mode.capitalize()+' process mode',loc='left',fontweight='bold');ax.grid(axis='y',alpha=.2)
axes[0].legend(loc='best',fontsize=10,ncol=2)
labels=[f"{v['arm']} {v['query'][0].upper()} R{v['renewals']}" for v in models['validation_affine']['cells']]
axes[-1].set_xticks(np.arange(18),labels,rotation=60,ha='right');axes[-1].set_xlabel('Design, query (S selective; F full), renewal count')
(r/'figures').mkdir(exist_ok=True)
fig.savefig(r/'figures/prediction_errors.png',dpi=240);fig.savefig(r/'figures/prediction_errors.svg');plt.close(fig)
