"""Bounded builder QC. Synthetic keys/data only; no agent tool execution/network.
Observation tests explicitly preserve unsupported guarantees. Seed: 20261102.
"""
import copy, concurrent.futures, hashlib, importlib.util, io, json, os, pathlib, stat
import subprocess, sys, tempfile, types, unittest, zipfile
from unittest.mock import patch
from agent_security_toolkit import approval, audit, pathpolicy, report, scenarios, strict_json
from agent_security_toolkit.approval import ApprovalAuthority, NonceLedger
from agent_security_toolkit.errors import AccessDenied, ApprovalError, AuditError, AuditBusy, ConfigError
from agent_security_toolkit.gate import Gate
from agent_security_toolkit.policy import Policy
from agent_security_toolkit.winfs import trusted_root, safe_read
KEY=b'synthetic-final-qc-key-only-32bytes';NOW=1800000000
SPEC={'schema_version':1,'tools':{'docs.read':{'risk':'low','path_arg':'path'},'docs.write':{'risk':'high','path_arg':'path'}},'agents':{'agent-a':{'allowed_tools':['docs.read','docs.write'],'allowed_paths':['docs/**']}},'approvers':['human-1']}
def act(i='final-1',tool='docs.read'):return {'action_id':i,'agent':'agent-a','tool':tool,'args':{'path':'docs/a.txt'}}
class MemoryAudit:
    def __init__(self):self.events=[]
    def append(self,event):self.events.append(event)
SOURCE=pathlib.Path(os.environ['REVIEW_SOURCE_ROOT'])
sp=importlib.util.spec_from_file_location('final_verifier',SOURCE/'tools/verify_release.py');v=importlib.util.module_from_spec(sp);sp.loader.exec_module(v)
def archive(extra=None,manifest_bytes=None,compression=zipfile.ZIP_DEFLATED):
    files={'README.md':b'synthetic data'};files.update(extra or {})
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',compression) as z:
        for p,b in files.items():z.writestr(v.ROOT+'/'+p,b)
        z.writestr(v.ROOT+'/SOURCE_MANIFEST.json',manifest_bytes if manifest_bytes is not None else json.dumps({p:hashlib.sha256(b).hexdigest() for p,b in files.items()}))
    return out.getvalue()
class FinalSecurity(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ast_final_synthetic_');self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name)
        self.auth=ApprovalAuthority(KEY,['human-1'],clock=lambda:NOW);self.mem=MemoryAudit()
    def gate(self,log=None):return Gate(Policy.from_dict(copy.deepcopy(SPEC)),self.auth,log or self.mem)
    def log(self):
        l=audit.AuditLog(str(self.base/'log'),str(self.base/'anchor'),KEY,clock=lambda:NOW);self.addCleanup(l.close);return l
    def reject_archive(self,b):
        with self.assertRaises(v.VerificationError):v.verify_bytes(b,hashlib.sha256(b).hexdigest())
    def test_01_forbidden_tool_newline_rejected(self):
        s=copy.deepcopy(SPEC);s['tools']['shell.exec\n']={'risk':'low'};s['agents']['agent-a']['allowed_tools'].append('shell.exec\n')
        with self.assertRaises(ConfigError):Policy.from_dict(s)
    def test_02_agent_identifier_newline_rejected(self):
        s=copy.deepcopy(SPEC);s['agents']['agent-a\n']=s['agents'].pop('agent-a')
        with self.assertRaises(ConfigError):Policy.from_dict(s)
    def test_03_approver_identifier_newline_rejected(self):
        s=copy.deepcopy(SPEC);s['approvers']=['human-1\n']
        with self.assertRaises(ConfigError):Policy.from_dict(s)
    def test_04_action_identifier_newline_denied(self):self.assertFalse(self.gate().submit(act('final-1\n'))['allowed'])
    def test_05_policy_boolean_schema_rejected(self):
        s=copy.deepcopy(SPEC);s['schema_version']=True
        with self.assertRaises(ConfigError):Policy.from_dict(s)
    def test_06_scenario_boolean_schema_rejected(self):
        cfg={'schema_version':True,'name':'synthetic','policy':copy.deepcopy(SPEC),'scenarios':[{'id':'s1','category':'synthetic','steps':[{'request':act(),'expect':'allow'}]}]}
        with self.assertRaises(ConfigError):scenarios.validate_config(cfg)
    def test_07_failed_close_not_counted_as_success(self):
        before=trusted_root.HANDLE_STATS['closed']
        with patch.object(trusted_root.w,'api',return_value=types.SimpleNamespace(close=lambda h:False)):
            with self.assertRaises(AccessDenied):trusted_root.release(123456)
        self.assertEqual(trusted_root.HANDLE_STATS['closed'],before)
    def test_08_successful_close_counted_once(self):
        before=trusted_root.HANDLE_STATS['closed'];closed=[]
        def close(h):closed.append(h);return True
        with patch.object(trusted_root.w,'api',return_value=types.SimpleNamespace(close=close)):trusted_root.release(123456)
        self.assertEqual(closed,[123456]);self.assertEqual(trusted_root.HANDLE_STATS['closed'],before+1)
    def test_09_null_handle_not_dispatched(self):
        with patch.object(trusted_root.w,'api') as api:trusted_root.release(None);api.assert_not_called()
    def test_10_close_exception_not_counted(self):
        before=trusted_root.HANDLE_STATS['closed']
        def close(h):raise OSError('synthetic close failure')
        with patch.object(trusted_root.w,'api',return_value=types.SimpleNamespace(close=close)),self.assertRaises(OSError):trusted_root.release(123456)
        self.assertEqual(trusted_root.HANDLE_STATS['closed'],before)
    def test_11_policy_float_schema_rejected(self):
        s=copy.deepcopy(SPEC);s['schema_version']=1.0
        with self.assertRaises(ConfigError):Policy.from_dict(s)
    def test_12_unknown_tool_denied(self):self.assertFalse(self.gate().submit(dict(act(),tool='unknown.read'))['allowed'])
    def test_13_unknown_agent_denied(self):self.assertFalse(self.gate().submit(dict(act(),agent='unknown'))['allowed'])
    def test_14_unknown_request_field_denied(self):self.assertFalse(self.gate().submit(dict(act(),admin=True))['allowed'])
    def test_15_missing_approval_denied(self):self.assertFalse(self.gate().submit(act(tool='docs.write'))['allowed'])
    def test_16_tampered_approver_denied(self):
        a=act(tool='docs.write');a['approval']=dict(self.auth.issue('human-1',a),approver='intruder');self.assertFalse(self.gate().submit(a)['allowed'])
    def test_17_expiry_boundary_denied(self):
        a=act(tool='docs.write');a['approval']=self.auth.issue('human-1',a,now=NOW-60,ttl_seconds=60);self.assertFalse(self.gate().submit(a)['allowed'])
    def test_18_changed_action_id_denied(self):
        a=act(tool='docs.write');tok=self.auth.issue('human-1',a);a['action_id']='other';a['approval']=tok;self.assertFalse(self.gate().submit(a)['allowed'])
    def test_19_changed_amount_arg_denied(self):
        a=act(tool='docs.write');tok=self.auth.issue('human-1',a);a['args']['amount_cents']=1;a['approval']=tok;self.assertFalse(self.gate().submit(a)['allowed'])
    def test_20_persistent_restart_replay_denied(self):
        path=str(self.base/'nonce');a=act(tool='docs.write');token=self.auth.issue('human-1',a)
        first=ApprovalAuthority(KEY,['human-1'],clock=lambda:NOW,ledger=NonceLedger(path));self.assertEqual(first.verify(token,a,'agent-a'),'human-1')
        again=ApprovalAuthority(KEY,['human-1'],clock=lambda:NOW,ledger=NonceLedger(path))
        with self.assertRaises(ApprovalError):again.verify(token,a,'agent-a')
    def test_21_shared_nonce_threads_at_most_one_success(self):
        a=act(tool='docs.write');token=self.auth.issue('human-1',a);p=str(self.base/'nonce')
        authorities=[ApprovalAuthority(KEY,['human-1'],clock=lambda:NOW,ledger=NonceLedger(p)) for _ in range(8)]
        def work(auth):
            try:auth.verify(token,a,'agent-a');return True
            except ApprovalError:return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:r=list(pool.map(work,authorities))
        self.assertEqual(sum(r),1)
    def test_22_audit_exception_refuses_authorization(self):
        class Broken:
            def append(self,e):raise OSError('synthetic disk full')
        r=self.gate(Broken()).submit(act());self.assertFalse(r['allowed']);self.assertNotIn('disk full',r['reason'])
    def test_23_duplicate_across_instances_documented_observation(self):
        self.assertTrue(self.gate().submit(act())['allowed']);self.assertTrue(self.gate().submit(act())['allowed'])
    def test_24_audit_anchor_interrupt_poisons_writer(self):
        l=self.log()
        with patch.object(l,'_write_anchor',side_effect=OSError('synthetic interrupt')),self.assertRaises(OSError):l.append({'test':1})
        with self.assertRaises(AuditError):l.append({'test':2})
        l.close();self.assertFalse(audit.verify(str(self.base/'log'),KEY,str(self.base/'anchor'))['ok'])
    def test_25_audit_short_write_detected(self):
        l=self.log()
        with patch.object(audit.os,'write',return_value=1),self.assertRaises(AuditError):l.append({'test':'short'})
        with self.assertRaises(AuditError):l.append({'test':'retry'})
    def test_26_nonce_short_write_releases_lock(self):
        p=self.base/'nonce';ledger=NonceLedger(str(p))
        with patch.object(approval.os,'write',return_value=1),self.assertRaises(ApprovalError):ledger.consume('a'*64)
        self.assertFalse(pathlib.Path(str(p)+'.consume.lock').exists());self.assertNotIn('a'*64,ledger)
    def test_27_nonce_crash_lock_fails_closed(self):
        p=str(self.base/'nonce');script="import os,sys;os.open(sys.argv[1]+'.consume.lock',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os._exit(0)"
        child=subprocess.run([sys.executable,'-c',script,p],capture_output=True,timeout=8);self.assertEqual(child.returncode,0)
        with self.assertRaises(ApprovalError):NonceLedger(p).consume('a'*64)
        self.assertTrue(pathlib.Path(p+'.consume.lock').exists())
    def test_28_audit_oversized_state_refused_bounded_fixture(self):
        l=self.log();l.close()
        (self.base/'log').write_bytes(b'12345')
        with patch.object(audit,'MAX_LOG_BYTES',4):self.assertFalse(audit.verify(str(self.base/'log'),KEY,str(self.base/'anchor'))['ok'])
    def test_29_ledger_oversized_state_refused(self):
        p=self.base/'nonce';p.write_bytes(b'a'*64+b'\n')
        with patch.object(approval,'MAX_LEDGER_BYTES',4),self.assertRaises(ApprovalError):NonceLedger(str(p))
    def test_30_duplicate_nested_json_keys_rejected(self):
        with self.assertRaises(ConfigError):strict_json.loads('{"outer":{"amount":1,"amount":2}}')
    def test_31_duplicate_audit_keys_rejected(self):
        l=self.log();l.append({'test':1});l.close();p=self.base/'log';p.write_bytes(p.read_bytes().replace(b'{',b'{"seq":1,',1));self.assertFalse(audit.verify(str(p),KEY,str(self.base/'anchor'))['ok'])
    def test_32_modified_anchor_rejected(self):
        l=self.log();l.append({'test':1});l.close();p=self.base/'anchor';a=json.loads(p.read_bytes());a['head']='f'*64;p.write_text(json.dumps(a));self.assertFalse(audit.verify(str(self.base/'log'),KEY,str(p))['ok'])
    def test_33_coordinated_rollback_documented_observation(self):
        l=self.log();l.append({'test':1});oldlog=(self.base/'log').read_bytes();oldanchor=(self.base/'anchor').read_bytes();l.append({'test':2});l.close()
        (self.base/'log').write_bytes(oldlog);(self.base/'anchor').write_bytes(oldanchor);self.assertTrue(audit.verify(str(self.base/'log'),KEY,str(self.base/'anchor'))['ok'])
    def test_34_archive_truncated_rejected(self):self.reject_archive(archive()[:-22])
    def test_35_archive_unsupported_compression_rejected(self):self.reject_archive(archive(compression=zipfile.ZIP_BZIP2))
    def test_36_manifest_wrong_type_rejected(self):self.reject_archive(archive(manifest_bytes=b'[]'))
    def test_37_manifest_nonhex_digest_rejected(self):self.reject_archive(archive(manifest_bytes=json.dumps({'README.md':'Z'*64})))
    def test_38_archive_tampered_manifest_member_rejected(self):self.reject_archive(archive(manifest_bytes=b'{"phantom":"' + b'0'*64+b'"}'))
    def test_39_archive_invalid_expected_hash_rejected(self):
        with self.assertRaises(v.VerificationError):v.verify_bytes(archive(),'a'*64+'\n')
    def test_40_archive_bomb_bound_small_fixture(self):
        with patch.object(v,'MAX_TOTAL',512):self.reject_archive(archive({'large.txt':b'X'*4096}))
    def test_41_archive_fifo_rejected(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:i=zipfile.ZipInfo(v.ROOT+'/fifo');i.external_attr=(stat.S_IFIFO|0o600)<<16;z.writestr(i,b'')
        self.reject_archive(b.getvalue())
    def test_42_report_no_overwrite_existing_json(self):
        p=self.base/'report.json';p.write_bytes(b'original synthetic')
        with self.assertRaises(FileExistsError):report.write(str(self.base),'report',{'synthetic':True},'synthetic')
        self.assertEqual(p.read_bytes(),b'original synthetic')
    def test_43_closed_audit_denies(self):l=self.log();l.close();self.assertFalse(self.gate(l).submit(act())['allowed'])
    def test_44_partial_log_refuses_restart(self):
        l=self.log();l.append({'test':1});l.close();p=self.base/'log';p.write_bytes(p.read_bytes()[:-1])
        with self.assertRaises(AuditError):audit.AuditLog(str(p),str(self.base/'anchor'),KEY)
        self.assertFalse(pathlib.Path(str(p)+'.lock').exists())
    def test_45_threaded_audit_chain_consistent(self):
        l=self.log()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:self.assertEqual(len(list(pool.map(lambda i:l.append({'synthetic':i}),range(32)))),32)
        l.close();r=audit.verify(str(self.base/'log'),KEY,str(self.base/'anchor'));self.assertTrue(r['ok']);self.assertEqual(r['entries'],32)
    def test_46_native_explicit_close_failure_invalidates_pin(self):
        pin=object.__new__(trusted_root.TrustedRoot);import threading;pin._guard=threading.RLock();pin._handle=123456
        with patch.object(trusted_root.w,'api',return_value=types.SimpleNamespace(close=lambda h:False)):
            with self.assertRaises(AccessDenied):pin.close()
        self.assertTrue(pin.closed)
        with self.assertRaises(AccessDenied):pin.validate()

    def test_61_release_generator_matches_its_verifier(self):
        out=self.base/'release'
        child=subprocess.run([sys.executable,str(SOURCE/'tools/make_release.py'),str(out)],capture_output=True,timeout=20)
        self.assertEqual(child.returncode,0,child.stderr.decode('utf-8','replace'))
        candidates=list(out.glob('*-source.zip'));self.assertEqual(len(candidates),1,'canonical source ZIP missing')
        data=candidates[0].read_bytes();result=v.verify_bytes(data,hashlib.sha256(data).hexdigest());self.assertTrue(result['ok'])
        with zipfile.ZipFile(candidates[0]) as z:self.assertIn(v.ROOT+'/review_tests/test_final_security.py',z.namelist())
    def test_62_release_reproducible_across_output_directories(self):
        for name in ['release-a','release-b']:
            child=subprocess.run([sys.executable,str(SOURCE/'tools/make_release.py'),str(self.base/name)],capture_output=True,timeout=20)
            self.assertEqual(child.returncode,0,child.stderr.decode('utf-8','replace'))
        a={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.base/'release-a').iterdir()}
        b={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.base/'release-b').iterdir()};self.assertEqual(a,b)
    def test_63_incomplete_report_pair_documented_observation(self):
        (self.base/'pair.md').write_bytes(b'original synthetic')
        with self.assertRaises(FileExistsError):report.write(str(self.base),'pair',{'synthetic':True},'synthetic')
        self.assertTrue((self.base/'pair.json').exists());self.assertEqual((self.base/'pair.md').read_bytes(),b'original synthetic')
    def test_64_release_refuses_existing_output_directory(self):
        child=subprocess.run([sys.executable,str(SOURCE/'tools/make_release.py'),str(self.base)],capture_output=True,timeout=20)
        self.assertNotEqual(child.returncode,0);self.assertEqual(list(self.base.iterdir()),[])

# Each hostile path is a separately collected test, not inflated subtest counts.
for number,path in enumerate(['../escape','docs/../../escape','C:\\outside','\\\\server\\share','docs/a:stream','docs/NUL.txt','docs/COM1','docs/a.','docs/a ','docs//a','docs/\x00a','docs/\u202ea','docs/\ud800','a/'*33+'x'],start=47):
    def check(self,path=path):
        with self.assertRaises(AccessDenied):pathpolicy.components(path)
    check.__name__='test_%02d_hostile_path_denied'%number;setattr(FinalSecurity,check.__name__,check)


# rc7 F3 oracle is deliberately independent of the generator and its manifest.
EXPECTED_RELEASE_PATHS = frozenset({
    '.gitignore',
    'CHANGELOG.md',
    'CONTRIBUTING.md',
    'DEPENDENCIES.json',
    'GITHUB_RELEASE_PREPARATION.md',
    'HARDENING_NOTES.md',
    'INSTALL.md',
    'KNOWN_LIMITATIONS.md',
    'LICENSE',
    'NOTICE',
    'LICENSING_STATUS.md',
    'README.md',
    'SBOM.cdx.json',
    'SECURITY.md',
    'SECURITY_ARCHITECTURE.md',
    'SOURCE_PROVENANCE.md',
    'TESTING.md',
    'THIRD_PARTY_LICENSES.md',
    'THREAT_MODEL.md',
    'USER_GUIDE.md',
    'configs/examples/baseline_scenarios.json',
    'pyproject.toml',
    'review_tests/test_final_security.py',
    'review_tests/test_rc8_cleanup.py',
    'review_tests/test_muse_followup.py',
    'review_tests/test_public_release.py',
    'review_tests/test_toolkit_adversarial.py',
    'review_tests/test_toolkit_windows_review.py',
    'src/agent_security_toolkit/__init__.py',
    'src/agent_security_toolkit/__main__.py',
    'src/agent_security_toolkit/approval.py',
    'src/agent_security_toolkit/audit.py',
    'src/agent_security_toolkit/cli.py',
    'src/agent_security_toolkit/errors.py',
    'src/agent_security_toolkit/fsprobe.py',
    'src/agent_security_toolkit/gate.py',
    'src/agent_security_toolkit/pathpolicy.py',
    'src/agent_security_toolkit/policy.py',
    'src/agent_security_toolkit/report.py',
    'src/agent_security_toolkit/scenarios.py',
    'src/agent_security_toolkit/strict_json.py',
    'src/agent_security_toolkit/winfs/__init__.py',
    'src/agent_security_toolkit/winfs/_win32.py',
    'src/agent_security_toolkit/winfs/safe_read.py',
    'src/agent_security_toolkit/winfs/trusted_root.py',
    'tests/__init__.py',
    'tests/_util.py',
    'tests/test_cli.py',
    'tests/test_packaging.py',
    'tests/test_pathpolicy.py',
    'tests/test_policy_gate.py',
    'tests/test_strict_json.py',
    'tests/test_winfs.py',
    'tools/build_wheel.py',
    'tools/make_release.py',
    'tools/run_full_suite.py',
    'tools/run_muse_evidence.py',
    'tools/verify_release.py',
})

class RC7Followups(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ast_rc7_synthetic_")
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)

    def configuration(self, identifier):
        return {"schema_version": 1, "name": "synthetic", "policy": copy.deepcopy(SPEC),
                "scenarios": [{"id": identifier, "category": "synthetic",
                               "steps": [{"request": act(), "expect": "allow"}]}]}

    def probe(self):
        from agent_security_toolkit.fsprobe import Probe
        probe = Probe.__new__(Probe)
        probe.base = str(self.directory)
        probe.results = []
        probe.race_iterations = 3
        return probe

    def test_rc7_valid_scenario_identifier_boundaries(self):
        for identifier in ["a", "A_1.x-y", "a" * 64]:
            with self.subTest(identifier=identifier):
                self.assertIsInstance(scenarios.validate_config(self.configuration(identifier)), Policy)

    def test_rc7_zero_swaps_never_pass(self):
        probe = self.probe()
        probe._record_root_swap_result(0, 3, 0, 0, 0, {}, {}, [])
        self.assertEqual(probe.results[0]["outcome"], "SKIPPED")
        self.assertFalse(probe.results[0]["passed"])

    def test_rc7_rename_denials_are_not_race_coverage(self):
        probe = self.probe()
        probe._record_root_swap_result(0, 3, 0, 0, 5, {"PermissionError errno=13 winerror=32": 5}, {}, [])
        record = probe.results[0]
        self.assertEqual(record["outcome"], "SKIPPED")
        self.assertFalse(record["passed"])
        self.assertIn("winerror=32", record["detail"])
        self.assertIn("rename_attempts=5", record["detail"])

    def test_rc7_successful_substitution_is_required_for_exercised(self):
        probe = self.probe()
        probe._record_root_swap_result(1, 2, 1, 0, 1, {}, {}, [])
        self.assertEqual(probe.results[0]["outcome"], "EXERCISED")
        self.assertTrue(probe.results[0]["passed"])

    def test_rc7_leak_fails_even_without_completed_swaps(self):
        probe = self.probe()
        probe._record_root_swap_result(0, 0, 0, 1, 1, {}, {}, [])
        self.assertEqual(probe.results[0]["outcome"], "LEAKED")
        self.assertFalse(probe.results[0]["passed"])

    def test_rc7_setup_and_unexpected_errors_fail(self):
        for setup, unexpected in [({"RuntimeError": 1}, []), ({}, ["OSError"])]:
            with self.subTest(setup=setup, unexpected=unexpected):
                probe = self.probe()
                probe._record_root_swap_result(1, 3, 0, 0, 1, {}, setup, unexpected)
                self.assertEqual(probe.results[0]["outcome"], "FAILED")
                self.assertFalse(probe.results[0]["passed"])

    def test_rc7_actual_probe_records_blocked_rename(self):
        from agent_security_toolkit import fsprobe
        failure = PermissionError(13, "synthetic rename denial")
        failure.winerror = 32
        stop = types.SimpleNamespace(is_set=unittest.mock.Mock(side_effect=[False, True]),
                                     set=lambda: None)

        class SynchronousThread:
            def __init__(self, target, daemon):
                self.target = target

            def start(self):
                self.target()

            def join(self, timeout):
                pass

            def is_alive(self):
                return False

        probe = self.probe()
        with patch.object(fsprobe.threading, "Event", return_value=stop), \
             patch.object(fsprobe.threading, "Thread", SynchronousThread), \
             patch.object(fsprobe.os, "rename", side_effect=failure), \
             patch.object(fsprobe.time, "sleep"), \
             patch("agent_security_toolkit.winfs.trusted_root.TrustedRoot"), \
             patch("agent_security_toolkit.winfs.safe_read.enroll", return_value={}), \
             patch("agent_security_toolkit.winfs.safe_read.read_enrolled", return_value=fsprobe.APPROVED):
            probe._root_swap_race()
        record = probe.results[0]
        self.assertEqual(record["outcome"], "SKIPPED")
        self.assertFalse(record["passed"])
        self.assertIn("swaps=0", record["detail"])
        self.assertIn("winerror=32", record["detail"])

    def test_rc7_intermediate_rename_requires_later_denial(self):
        probe = self.probe()
        with patch("agent_security_toolkit.winfs.trusted_root.TrustedRoot"), \
             patch("agent_security_toolkit.winfs.safe_read.enroll", return_value={"synthetic": True}), \
             patch("agent_security_toolkit.winfs.safe_read.read_enrolled", side_effect=AccessDenied("synthetic denial")):
            probe._intermediate_directory_rename()
        self.assertTrue((self.directory / "intermediate_root/docs_moved/a.txt").is_file())
        self.assertEqual(probe.results[0]["outcome"], "DENIED")
        self.assertTrue(probe.results[0]["passed"])

    def test_rc7_intermediate_setup_failure_stays_skip(self):
        from agent_security_toolkit import fsprobe
        probe = self.probe()
        with patch("agent_security_toolkit.winfs.trusted_root.TrustedRoot"), \
             patch("agent_security_toolkit.winfs.safe_read.enroll", return_value={"synthetic": True}), \
             patch.object(fsprobe.os, "rename", side_effect=PermissionError(13, "synthetic denial")):
            probe._intermediate_directory_rename()
        self.assertEqual(probe.results[0]["outcome"], "SKIPPED")
        self.assertFalse(probe.results[0]["passed"])

    @unittest.skipUnless(os.name == "nt", "Native Windows intermediate-directory rename")
    def test_rc7_native_intermediate_rename_fails_closed(self):
        probe = self.probe()
        probe._intermediate_directory_rename()
        result = probe.results[0]
        if result["outcome"] == "SKIPPED":
            self.skipTest(result["detail"])
        self.assertEqual(result["outcome"], "DENIED")
        self.assertTrue(result["passed"])

    def test_rc7_release_inventory_exact(self):
        output = self.directory / "release"
        child = subprocess.run([sys.executable, str(SOURCE / "tools/make_release.py"), str(output)],
                               capture_output=True, timeout=20)
        self.assertEqual(child.returncode, 0, child.stderr.decode("utf-8", "replace"))
        archives = list(output.glob("*-source.zip"))
        self.assertEqual(len(archives), 1)
        with zipfile.ZipFile(archives[0]) as archive:
            names = archive.namelist()
            relative = [name.split("/", 1)[1] for name in names]
            self.assertEqual(len(relative), len(set(relative)), "duplicate release members")
            self.assertEqual(set(relative), EXPECTED_RELEASE_PATHS | {"SOURCE_MANIFEST.json"})
            manifest = json.loads(archive.read(v.ROOT + "/SOURCE_MANIFEST.json"))
            self.assertEqual(set(manifest), EXPECTED_RELEASE_PATHS)

    def test_rc7_architecture_documents_probe_boundary(self):
        text = (SOURCE / "SECURITY_ARCHITECTURE.md").read_text(encoding="utf-8")
        for required in ["## fsprobe", "GetSystemDirectoryW", "cmd.exe", "WinError 1314", "zero successful substitutions"]:
            with self.subTest(required=required):
                self.assertIn(required, text)


def _scenario_identifier_rejection(identifier):
    def test(self):
        with self.assertRaises(ConfigError):
            scenarios.validate_config(self.configuration(identifier))
    return test


for index, identifier in enumerate(["", "\n", " ", "../x", "a/b", "a\\b", "a\n", "a\r\n", "a\x00", "a\t", " a", "a ", "a" * 65, "-a", "\u0430"], start=1):
    setattr(RC7Followups, "test_rc7_invalid_scenario_id_%02d" % index,
            _scenario_identifier_rejection(identifier))
