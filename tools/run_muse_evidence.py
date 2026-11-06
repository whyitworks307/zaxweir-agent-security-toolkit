"""Run one test module, retaining actual failures/errors/skips in JSON and text."""
import argparse, importlib.util, io, json, os, sys, unittest
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--test',required=True);p.add_argument('--output',required=True)
a=p.parse_args();root=Path(a.source).resolve();sys.path.insert(0,str(root/'src'));os.environ['PYTHONPATH']=str(root/'src');os.environ['PYTHONDONTWRITEBYTECODE']='1';os.environ['REVIEW_SOURCE_ROOT']=str(root)
spec=importlib.util.spec_from_file_location('review_probe',a.test);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Record(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.records=[]
    def addSuccess(self,t):super().addSuccess(t);self.records.append({'test':t.id(),'outcome':'PASS'})
    def addFailure(self,t,e):super().addFailure(t,e);self.records.append({'test':t.id(),'outcome':'FAIL','detail':self._exc_info_to_string(e,t)})
    def addError(self,t,e):super().addError(t,e);self.records.append({'test':t.id(),'outcome':'ERROR','detail':self._exc_info_to_string(e,t)})
    def addSubTest(self,t,sub,err):
        super().addSubTest(t,sub,err)
        if err is not None:self.records.append({'test':t.id(),'subtest':str(sub),'outcome':'FAIL' if issubclass(err[0],t.failureException) else 'ERROR','detail':self._exc_info_to_string(err,t)})
    def addSkip(self,t,r):super().addSkip(t,r);self.records.append({'test':t.id(),'outcome':'SKIP','reason':r})
out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
with out.with_suffix('.log').open('w',encoding='utf-8') as stream:
    result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Record).run(unittest.defaultTestLoader.loadTestsFromModule(module))
summary={'python':sys.version,'platform':sys.platform,'source':str(root),'collected':result.testsRun,'passed':sum(x['outcome']=='PASS' for x in result.records),'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'failed_test_methods':len({t['test'] for t in result.records if t['outcome']=='FAIL'}),'error_test_methods':len({t['test'] for t in result.records if t['outcome']=='ERROR'}),'tests':result.records}
out.with_suffix('.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in summary.items() if k!='tests'}));sys.exit(not result.wasSuccessful())
