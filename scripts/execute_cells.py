"""Execute the original plain-Python notebook cells without a kernel server.

The supplied six cells use only ordinary Python and print output, no magics or
rich displays. This runner captures those streams in a valid notebook and
records its execution engine explicitly. It does not claim Jupyter execution.
"""
from pathlib import Path
import json,sys,os,io,contextlib,time,traceback
root=Path(sys.argv[1]).resolve();os.chdir(root);sys.dont_write_bytecode=True
nb=json.loads((root/'VITAL_Q_Analysis.ipynb').read_text());scope={'__name__':'__main__'};count=0
for cell in nb['cells']:
    if cell['cell_type']!='code':continue
    count+=1;source=''.join(cell['source']);capture=io.StringIO();cell['outputs']=[];cell['execution_count']=count
    try:
        with contextlib.redirect_stdout(capture),contextlib.redirect_stderr(capture):
            exec(compile(source,f'notebook-cell-{count}','exec'),scope)
    except BaseException as exc:
        cell['outputs']=[{'output_type':'error','ename':type(exc).__name__,'evalue':str(exc),'traceback':traceback.format_exc().splitlines()}]
        (root/'VITAL_Q_Analysis_Failed.ipynb').write_text(json.dumps(nb,indent=1)+'\n')
        raise
    if capture.getvalue():cell['outputs']=[{'output_type':'stream','name':'stdout','text':capture.getvalue().splitlines(keepends=True)}]
    print(f'Cell {count} passed',flush=True)
nb.setdefault('metadata',{})['reproduction_execution']={'engine':'sequential Python exec, shared namespace, isolated subprocess; not a Jupyter kernel','python':sys.version,'completed_unix':time.time(),'code_cells':count}
(root/'VITAL_Q_Analysis_Reexecuted.ipynb').write_text(json.dumps(nb,indent=1)+'\n')
assert count==6
