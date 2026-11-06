import argparse,importlib.util,json,os,pathlib,sys,unittest
p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--output',required=True);a=p.parse_args()
root=pathlib.Path(a.source).resolve();sys.path.insert(0,str(root/'src'));sys.path.insert(0,str(root));os.environ['PYTHONPATH']=str(root/'src');os.environ['AST_TEST_SEED']='20261102';os.environ['AST_FUZZ_N']='2000';os.environ['PYTHONDONTWRITEBYTECODE']='1'
class Record(unittest.TextTestResult):
    def __init__(self,*a,**k):super().__init__(*a,**k);self.records=[]
    def addSuccess(self,t):super().addSuccess(t);self.records.append({'test':t.id(),'outcome':'PASS'})
    def addFailure(self,t,e):super().addFailure(t,e);self.records.append({'test':t.id(),'outcome':'FAIL','detail':self._exc_info_to_string(e,t)})
    def addError(self,t,e):super().addError(t,e);self.records.append({'test':t.id(),'outcome':'ERROR','detail':self._exc_info_to_string(e,t)})
    def addSkip(self,t,r):super().addSkip(t,r);self.records.append({'test':t.id(),'outcome':'SKIP','reason':r})
out=pathlib.Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
suite=unittest.defaultTestLoader.discover(str(root/'tests'),top_level_dir=str(root))
with out.with_suffix('.log').open('w',encoding='utf-8') as f:r=unittest.TextTestRunner(stream=f,verbosity=2,resultclass=Record).run(suite)
d={'platform':sys.platform,'python':sys.version,'source':str(root),'seed':20261102,'fuzz_n':2000,'collected':r.testsRun,'passed':sum(t['outcome']=='PASS' for t in r.records),'failures':len(r.failures),'errors':len(r.errors),'skipped':len(r.skipped),'tests':r.records}
out.with_suffix('.json').write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8');print(json.dumps({k:v for k,v in d.items() if k!='tests'}));sys.exit(not r.wasSuccessful())
