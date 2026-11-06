"""GPT-authored safe reproductions of actual Muse F01-F14/T01-T22 suggestions.
All files, keys and paths are synthetic. No network, real keys, or large allocations.
Observation tests for documented limitations are not vulnerability fixes.
"""
import builtins,copy,hashlib,io,json,os,pathlib,subprocess,sys,tempfile,time,types,unittest
from unittest.mock import patch
from agent_security_toolkit import approval,audit,fsprobe,pathpolicy,report,strict_json,__version__
from agent_security_toolkit.approval import ApprovalAuthority,NonceLedger,action_digest
from agent_security_toolkit.errors import ApprovalError,AuditError,AuditBusy,ConfigError,AccessDenied
from agent_security_toolkit.gate import Gate
from agent_security_toolkit.policy import Policy
KEY=b'fictional-review-key-not-a-secret-32'
NOW=1800000000
SPEC={'schema_version':1,'tools':{'docs.read':{'risk':'low','path_arg':'path'},'docs.write':{'risk':'high','path_arg':'path'}},'agents':{'agent-a':{'allowed_tools':['docs.read','docs.write'],'allowed_paths':['docs/**']}},'approvers':['human-1']}
def act(i='a1',tool='docs.read'):return {'action_id':i,'agent':'agent-a','tool':tool,'args':{'path':'docs/a.txt'}}
class MemoryAudit:
    def __init__(self):self.events=[]
    def append(self,e):self.events.append(e)
class Followup(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ast_muse_synthetic_');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name)
        self.auth=ApprovalAuthority(KEY,['human-1'],clock=lambda:NOW);self.events=MemoryAudit()
    def gate(self,events=None):return Gate(Policy.from_dict(copy.deepcopy(SPEC)),self.auth,events or self.events)
    def log(self):
        l=audit.AuditLog(str(self.base/'log'),str(self.base/'anchor'),KEY);self.addCleanup(l.close);return l
    def test_01_cross_process_preopened_nonce(self):
        token=self.auth.issue('human-1',act(tool='docs.write'));tokenfile=self.base/'token';tokenfile.write_text(json.dumps(token))
        script="""import json,pathlib,sys,time
from agent_security_toolkit.approval import ApprovalAuthority,NonceLedger
from agent_security_toolkit.errors import ApprovalError
b=pathlib.Path(sys.argv[1]);n=sys.argv[2]
a=ApprovalAuthority(b'fictional-review-key-not-a-secret-32',['human-1'],clock=lambda:1800000000,ledger=NonceLedger(str(b/'nonce')))
(b/('ready'+n)).touch()
end=time.monotonic()+8
while not (b/'release').exists():
 if time.monotonic()>end:raise SystemExit(3)
 time.sleep(.005)
try:a.verify(json.loads((b/'token').read_text()),{'action_id':'a1','agent':'agent-a','tool':'docs.write','args':{'path':'docs/a.txt'}},'agent-a');result='ALLOW'
except ApprovalError:result='DENY'
(b/('result'+n)).write_text(result)
"""
        ps=[subprocess.Popen([sys.executable,'-c',script,str(self.base),str(i)],stdout=subprocess.PIPE,stderr=subprocess.PIPE) for i in range(2)]
        try:
            end=time.monotonic()+8
            while not all((self.base/('ready'+str(i))).exists() for i in range(2)):
                if time.monotonic()>end:self.fail('child preload deadline')
                time.sleep(.005)
            (self.base/'release').touch()
            for p in ps:
                out,err=p.communicate(timeout=10);self.assertEqual(p.returncode,0,err.decode())
            results=[(self.base/('result'+str(i))).read_text() for i in range(2)]
            self.assertEqual(results.count('ALLOW'),1,results)
        finally:
            for p in ps:
                if p.poll() is None:p.kill();p.wait()
    def test_02_nonce_corruption_after_open_denies(self):
        p=self.base/'nonce';l=NonceLedger(str(p));p.write_bytes(b'corrupt\n')
        with self.assertRaises(ApprovalError):l.consume('a'*64)
    def test_03_audit_reads_are_bounded(self):
        l=self.log();l.append({'fictional':True});l.close();real=builtins.open
        class Guard:
            def __init__(s,f):s.f=f
            def __enter__(s):s.f.__enter__();return s
            def __exit__(s,*a):return s.f.__exit__(*a)
            def read(s,n=-1):
                if n<0:raise AssertionError('unbounded audit read')
                return s.f.read(n)
        def op(p,*a,**k):
            f=real(p,*a,**k);return Guard(f) if os.fspath(p)==str(self.base/'log') else f
        with patch('builtins.open',side_effect=op):self.assertTrue(audit.verify(str(self.base/'log'),KEY,str(self.base/'anchor'))['ok'])
    def test_04_nonce_reads_are_bounded(self):
        p=self.base/'nonce';p.write_bytes(b'a'*64+b'\n');real=builtins.open
        class Guard:
            def __enter__(s):s.f=real(p,'rb');return s
            def __exit__(s,*a):s.f.close()
            def read(s,n=-1):
                if n<0:raise AssertionError('unbounded nonce read')
                return s.f.read(n)
        with patch('builtins.open',return_value=Guard()):NonceLedger(str(p))
    def test_05_crash_lock_requires_review(self):
        script="from agent_security_toolkit.audit import AuditLog;import os,sys;AuditLog(sys.argv[1],sys.argv[2],b'fictional-review-key-not-a-secret-32');os._exit(0)"
        subprocess.run([sys.executable,'-c',script,str(self.base/'log'),str(self.base/'anchor')],check=True,timeout=5)
        with self.assertRaises(AuditBusy):self.log()
    def test_06_failed_audit_consumes_id_fail_closed_observation(self):
        class Flaky(MemoryAudit):
            fail=True
            def append(s,e):
                if s.fail:raise OSError('synthetic disk full')
                super().append(e)
        f=Flaky();g=self.gate(f);self.assertFalse(g.submit(act())['allowed']);f.fail=False
        r=g.submit(act());self.assertFalse(r['allowed']);self.assertIn('duplicate',r['reason'])
    def test_07_allow_event_has_action_digest_without_plain_args(self):
        a=act();self.assertTrue(self.gate().submit(a)['allowed']);e=self.events.events[-1]
        self.assertEqual(e.get('action_digest'),action_digest(a));self.assertNotIn('args',e)
    def test_08_issue_rejects_invalid_ttl(self):
        for ttl in [0,-5,5000,1.5,'60',True]:
            with self.subTest(ttl=ttl),self.assertRaises(ConfigError):self.auth.issue('human-1',act(),ttl_seconds=ttl)
    def test_09_extra_arguments_documented_limit(self):
        p=Policy.from_dict(copy.deepcopy(SPEC));args={'path':'docs/a','mode':'overwrite','ｅｌｅｖａｔｅ':True}
        self.assertTrue(p.authorize('agent-a','docs.read',args).allowed)
        for k in ['ELEVATE','run_as','bypass_approval']:
            d=p.authorize('agent-a','docs.read',{'path':'docs/a',k:True});self.assertFalse(d.allowed);self.assertTrue(d.escalation_attempt)
    def test_10_binary_key_change_must_invalidate(self):
        l=self.log();l.append({'fictional':True});l.close()
        self.assertTrue(audit.verify(str(self.base/'log'),KEY,str(self.base/'anchor'))['ok'])
        self.assertFalse(audit.verify(str(self.base/'log'),KEY+b'\n',str(self.base/'anchor'))['ok'])
    def test_11_lexical_shortname_limits_observation(self):
        self.assertEqual(pathpolicy.components('LONGNA~1.TXTX'),('LONGNA~1.TXTX',))
        self.assertFalse(pathpolicy.matches(r'a\b','a/b'))
    def test_12_json_depth_and_encoding_edges(self):
        self.assertEqual(strict_json.loads('['*32+'0'+']'*32),strict_json.loads('['*32+'0'+']'*32))
        for raw in ['['*33+'0'+']'*33,'{"x":{"a":1,"a":2}}',b'\xff',b'{} trailing']:
            with self.subTest(raw=str(raw)[:30]),self.assertRaises(ConfigError):strict_json.loads(raw)
        self.assertEqual(strict_json.loads('\ufeff{}'),{})
    def test_13_config_read_is_already_bounded(self):
        fake=io.BytesIO(b'{}');seen=[]
        class F:
            def __enter__(s):return s
            def __exit__(s,*a):pass
            def read(s,n=-1):seen.append(n);return fake.read(n)
        with patch('builtins.open',return_value=F()):self.assertEqual(strict_json.load_file('synthetic.json'),{})
        self.assertEqual(seen,[strict_json.MAX_BYTES+1])
    def test_14_gate_request_boundaries(self):
        for n in [127,128]:self.assertTrue(self.gate().submit(act('x'*n))['allowed'])
        for a in [act('x'*129),act(''),dict(act(),args=[]),dict(act(),args={'path':True}),dict(act(),extra=True),dict(act(),action_id=123)]:
            with self.subTest(a=str(a)[:60]):self.assertFalse(self.gate().submit(a)['allowed'])
    def test_15_token_serialization_and_rejections(self):
        for mode in ['str','bytes']:
            t=self.auth.issue('human-1',act());raw=json.dumps(t);raw=raw.encode() if mode=='bytes' else raw
            self.assertEqual(self.auth.verify(raw,act(),'agent-a'),'human-1')
        for field,value in [('v',2),('nonce','A'*64),('extra',1)]:
            t=self.auth.issue('human-1',act());t[field]=value
            with self.assertRaises(ApprovalError):self.auth.verify(t,act(),'agent-a')
    def test_16_clock_boundaries(self):
        self.assertEqual(self.auth.verify(self.auth.issue('human-1',act(),now=NOW+30),act(),'agent-a'),'human-1')
        with self.assertRaises(ApprovalError):self.auth.verify(self.auth.issue('human-1',act(),now=NOW+31),act(),'agent-a')
        t=self.auth.issue('human-1',act(),now=NOW-300)
        with self.assertRaises(ApprovalError):self.auth.verify(t,act(),'agent-a')
    def test_17_torn_anchor_and_blank_log(self):
        l=self.log();l.append({'fictional':True});l.close();ap=self.base/'anchor';original=ap.read_bytes();ap.write_bytes(original[:len(original)//2])
        self.assertFalse(audit.verify(str(self.base/'log'),KEY,str(ap))['ok']);ap.write_bytes(original)
        with (self.base/'log').open('ab') as f:f.write(b'\n')
        self.assertFalse(audit.verify(str(self.base/'log'),KEY,str(ap))['ok'])
    def test_18_nonce_state_path_is_trusted_observation(self):
        target=self.base/'synthetic-target';target.write_bytes(b'');link=self.base/'ledger-link'
        try:link.symlink_to(target)
        except OSError as e:self.skipTest('symlink unavailable: '+type(e).__name__)
        NonceLedger(str(link)).consume('a'*64);self.assertEqual(target.read_bytes(),b'a'*64+b'\n')
    def test_19_report_collision_preserves_existing_files(self):
        report.write(str(self.base),'synthetic',{'fictional':True},'original');before={p.name:p.read_bytes() for p in self.base.iterdir()}
        with self.assertRaises(FileExistsError):report.write(str(self.base),'synthetic',{},'new')
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.base.iterdir()})
    def test_20_version_consistency_and_no_runtime_dependencies(self):
        import tomllib
        root=pathlib.Path(os.environ['REVIEW_SOURCE_ROOT']);p=tomllib.loads((root/'pyproject.toml').read_text())
        self.assertEqual(p['project']['version'],__version__);self.assertFalse(p['project'].get('dependencies',[]))
    def test_21_unique_atomic_temp_ignores_legacy_symlink(self):
        target=self.base/'fictional-victim';target.write_bytes(b'preserve');out=self.base/'anchor';tmp=pathlib.Path(str(out)+'.tmp-'+str(os.getpid()))
        try:tmp.symlink_to(target)
        except OSError as e:self.skipTest('symlink unavailable: '+type(e).__name__)
        audit._write_atomic(str(out),b'overwrite')
        self.assertEqual(target.read_bytes(),b'preserve');self.assertTrue(tmp.is_symlink());self.assertEqual(out.read_bytes(),b'overwrite')
    def test_22_probe_exception_paths_are_redacted(self):
        p=fsprobe.Probe.__new__(fsprobe.Probe);p.results=[];p.pin=object();p.enr=object()
        fake=types.ModuleType('agent_security_toolkit.winfs.safe_read')
        def read(*a,**k):raise OSError(5,'synthetic denied',r'C:\FICTIONAL_USER\private\file.txt')
        fake.read_enrolled=read
        with patch.dict(sys.modules,{'agent_security_toolkit.winfs.safe_read':fake}):p._attempt('synthetic','privacy','docs/a')
        self.assertNotIn('FICTIONAL_USER',json.dumps(p.results))
    def test_23_gate_restart_duplicate_limit_observation(self):
        self.assertTrue(self.gate().submit(act())['allowed']);self.assertTrue(self.gate().submit(act())['allowed'])
    def test_24_report_pair_not_atomic_observation(self):
        (self.base/'collision.md').write_text('existing')
        with self.assertRaises(FileExistsError):report.write(str(self.base),'collision',{'fictional':True},'new')
        self.assertTrue((self.base/'collision.json').exists());self.assertEqual((self.base/'collision.md').read_text(),'existing')
    def test_25_oversized_audit_is_explicitly_rejected(self):
        p=self.base/'large-log';p.write_bytes(b'X'*(8*1024*1024+1))
        r=audit.verify(str(p),KEY);self.assertFalse(r['ok']);self.assertIn('log size limit',' '.join(r['problems']).lower())
    def test_26_oversized_nonce_ledger_is_explicitly_rejected(self):
        p=self.base/'large-ledger';p.write_bytes(b'X'*(1024*1024+1))
        with self.assertRaisesRegex(ApprovalError,'size limit'):NonceLedger(str(p))
    def test_27_audit_append_stops_before_size_limit(self):
        l=self.log();limit=getattr(audit,'MAX_LOG_BYTES',8*1024*1024)
        with open(l.log_path,'wb') as f:f.truncate(limit)
        with self.assertRaises(AuditError):l.append({'fictional':True})
    def test_28_nonce_append_stops_before_size_limit(self):
        p=self.base/'nonce';l=NonceLedger(str(p));real=os.fstat
        def stat(fd):
            class S:st_size=1024*1024
            return S()
        with patch('os.fstat',side_effect=stat),self.assertRaises(ApprovalError):l.consume('a'*64)
    def test_29_unexpected_reader_exception_is_not_a_passing_attack(self):
        p=fsprobe.Probe.__new__(fsprobe.Probe);p.results=[];p.pin=object();p.enr=object()
        fake=types.ModuleType('agent_security_toolkit.winfs.safe_read')
        def read(*a,**k):raise RuntimeError('synthetic unexpected failure')
        fake.read_enrolled=read
        with patch.dict(sys.modules,{'agent_security_toolkit.winfs.safe_read':fake}):p._attempt('synthetic','reliability','docs/a')
        self.assertEqual(p.results[0]['outcome'],'FAILED');self.assertFalse(p.results[0]['passed'])
