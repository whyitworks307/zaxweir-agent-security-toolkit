"""GPT-6.1-authored probes, not Muse suggestions or independent Vex QC.

Run with PYTHONPATH pointing at one disposable candidate's src directory.
Only fictional data and temporary directories. No network or external keys.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from agent_security_toolkit import audit, pathpolicy, scenarios
from agent_security_toolkit.approval import ApprovalAuthority, NonceLedger
from agent_security_toolkit.errors import ApprovalError, AuditError, AuditBusy, ConfigError, AccessDenied
from agent_security_toolkit.gate import Gate
from agent_security_toolkit.policy import Policy
from agent_security_toolkit.strict_json import canonical, loads

KEY = b'fictional-unit-test-key-only-00000'
NOW = 1800000000
POLICY = {'schema_version': 1, 'tools': {'docs.read': {'risk': 'low', 'path_arg': 'path'},
          'docs.write': {'risk': 'high', 'path_arg': 'path'}},
          'agents': {'agent-a': {'allowed_tools': ['docs.read', 'docs.write'], 'allowed_paths': ['docs/**']}},
          'approvers': ['human-1']}


def action(identifier='one', tool='docs.write'):
    return {'action_id': identifier, 'agent': 'agent-a', 'tool': tool, 'args': {'path': 'docs/a.txt'}}


class Adversarial(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ast_review_')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.lp, self.ap = str(self.base/'log.jsonl'), str(self.base/'anchor.json')
        self.auth = ApprovalAuthority(KEY, ['human-1'], clock=lambda: NOW)

    def log(self):
        log = audit.AuditLog(self.lp, self.ap, KEY, clock=lambda: NOW)
        self.addCleanup(log.close)
        return log

    def gate(self, log):
        return Gate(Policy.from_dict(copy.deepcopy(POLICY)), self.auth, log)

    def test_01_empty_initialized_log_verifies(self):
        self.log().close()
        self.assertTrue(audit.verify(self.lp, KEY, self.ap)['ok'])

    def test_02_empty_initialized_log_reopens(self):
        self.log().close()
        self.log().close()

    def test_03_nonce_short_write_must_not_consume_successfully(self):
        auth = ApprovalAuthority(KEY, ['human-1'], clock=lambda: NOW, ledger=NonceLedger(str(self.base/'nonce')))
        tok = auth.issue('human-1', action())
        with patch('os.write', return_value=0):
            with self.assertRaises((ApprovalError, OSError)):
                auth.verify(tok, action(), 'agent-a')

    def test_04_preopened_nonce_ledgers_share_replay_state(self):
        p = str(self.base/'nonce')
        a = ApprovalAuthority(KEY, ['human-1'], clock=lambda: NOW, ledger=NonceLedger(p))
        b = ApprovalAuthority(KEY, ['human-1'], clock=lambda: NOW, ledger=NonceLedger(p))
        tok = a.issue('human-1', action())
        a.verify(tok, action(), 'agent-a')
        with self.assertRaises(ApprovalError):
            b.verify(tok, action(), 'agent-a')

    def test_05_log_unicode_mac_is_invalid_without_exception(self):
        log = self.log(); log.append({'event': 'fictional'}); log.close()
        rec = json.loads(Path(self.lp).read_text()); rec['mac'] = '\u2603'*64
        Path(self.lp).write_bytes(canonical(rec)+b'\n')
        self.assertFalse(audit.verify(self.lp, KEY, self.ap)['ok'])

    def test_06_anchor_unicode_mac_is_invalid_without_exception(self):
        log = self.log(); log.append({'event': 'fictional'}); log.close()
        rec = json.loads(Path(self.ap).read_text()); rec['mac'] = '\u2603'*64
        Path(self.ap).write_bytes(canonical(rec))
        self.assertFalse(audit.verify(self.lp, KEY, self.ap)['ok'])

    def test_07_token_unicode_mac_raises_approval_error(self):
        tok = self.auth.issue('human-1', action()); tok['mac'] = '\u2603'*64
        with self.assertRaises(ApprovalError):
            self.auth.verify(tok, action(), 'agent-a')

    def test_08_oversized_anchor_tail_not_ignored(self):
        log = self.log(); log.append({'event': 'fictional'}); log.close()
        raw = Path(self.ap).read_bytes()
        Path(self.ap).write_bytes(raw+b' '*(audit.MAX_LINE-len(raw))+b'UNTRUSTED_TRAILER')
        self.assertFalse(audit.verify(self.lp, KEY, self.ap)['ok'])

    def test_09_partial_append_poisons_writer(self):
        log = self.log(); gate = self.gate(log); real = os.write
        partial = [False]
        def short(fd, data):
            if not partial[0]:
                partial[0] = True
                return real(fd, data[:7])
            return real(fd, data)
        with patch('os.write', side_effect=short):
            self.assertFalse(gate.submit(action('first','docs.read'))['allowed'])
        self.assertFalse(gate.submit(action('second','docs.read'))['allowed'],
                         'A writer with a torn log must not authorize later actions')

    def test_10_short_anchor_write_never_allows(self):
        log = self.log(); gate = self.gate(log); real = os.write
        def short_anchor(fd, data):
            if not data.endswith(b'\n'):
                return 0
            return real(fd, data)
        with patch('os.write', side_effect=short_anchor):
            self.assertFalse(gate.submit(action('first','docs.read'))['allowed'])

    def test_11_action_scope_change_rejects(self):
        tok = self.auth.issue('human-1', action())
        changed = action(); changed['args']['path'] = 'docs/other.txt'
        with self.assertRaises(ApprovalError): self.auth.verify(tok, changed, 'agent-a')

    def test_12_expiry_boundary_rejects(self):
        tok = self.auth.issue('human-1', action(), now=NOW-300)
        with self.assertRaises(ApprovalError): self.auth.verify(tok, action(), 'agent-a')

    def test_13_future_clock_beyond_skew_rejects(self):
        tok = self.auth.issue('human-1', action(), now=NOW+31)
        with self.assertRaises(ApprovalError): self.auth.verify(tok, action(), 'agent-a')

    def test_14_persisted_nonce_corruption_rejects(self):
        p=self.base/'nonce'; p.write_bytes(b'not-a-complete-nonce\n')
        with self.assertRaises(ApprovalError): NonceLedger(str(p))

    def test_15_unknown_request_field_denied(self):
        gate = self.gate(self.log()); req=action('unknown','docs.read');req['approved']=True
        self.assertFalse(gate.submit(req)['allowed'])

    def test_16_case_variant_escalation_denied(self):
        gate = self.gate(self.log());req=action('case','docs.read');req['args']['RuN_As']='administrator'
        out=gate.submit(req);self.assertFalse(out['allowed']);self.assertTrue(out['escalation_attempt'])

    def test_17_bad_scenario_identifier_is_config_error(self):
        cfg={'schema_version':1,'name':'fictional','policy':copy.deepcopy(POLICY),
             'scenarios':[{'id':[],'category':'invalid','steps':[{'request':{},'expect':'deny'}]}]}
        with self.assertRaises(ConfigError): scenarios.validate_config(cfg)

    def test_18_runner_can_record_nonobject_request_denial(self):
        cfg={'schema_version':1,'name':'fictional','policy':copy.deepcopy(POLICY),
             'scenarios':[{'id':'nonobject','category':'invalid','steps':[{'request':[], 'expect':'deny'}]}]}
        result=scenarios.run_config(cfg)
        self.assertTrue(result['steps'][0]['passed'])
        self.assertEqual(result['steps'][0]['actual'],'deny')

    def test_19_pattern_adversarial_match_is_bounded(self):
        # Run in a disposable child; a timeout stops work rather than hanging QC.
        code='from agent_security_toolkit.pathpolicy import matches; print(matches("**/"*12+"never", "/".join(["a"]*24)))'
        try:
            r=subprocess.run([sys.executable,'-B','-c',code],capture_output=True,text=True,timeout=2)
        except subprocess.TimeoutExpired:
            self.fail('24-component request with 12 recursive patterns exceeded a 2-second child budget')
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),'False')

    def test_20_pattern_depth_has_a_bound(self):
        with self.assertRaises(AccessDenied): pathpolicy.validate_pattern('/'.join(['**']*100))

    def test_21_traversal_device_format_inputs_denied(self):
        for path in ['../x','docs/../x','docs/a.txt:secret','\\\\server\\share','C:relative','docs/COM\u00b9','docs/a\u200bb']:
            with self.subTest(path=repr(path)):
                with self.assertRaises(AccessDenied): pathpolicy.components(path)

    def test_22_valid_path_controls_remain_distinct(self):
        self.assertTrue(pathpolicy.matches('docs/**','docs/ss.txt'))
        self.assertFalse(pathpolicy.matches('docs/ss.txt','docs/\u00df.txt'))
        self.assertFalse(pathpolicy.matches('docs/a.txt','DOCS/a.txt'))

    def test_23_wrong_audit_key_failure_releases_lock(self):
        log=self.log();log.append({'event':'fictional'});log.close()
        with self.assertRaises(AuditError): audit.AuditLog(self.lp,self.ap,b'x'*32)
        self.log().close()

    def test_24_single_writer_still_denied(self):
        self.log()
        with self.assertRaises(AuditBusy): audit.AuditLog(self.lp,self.ap,KEY)

    def test_25_json_duplicate_and_overflow_rejected(self):
        for raw in ['{"x":1,"x":2}','{"amount":1e999}', '[[['*15+'0'+']]]'*15]:
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(ConfigError): loads(raw)

    def test_26_old_log_and_anchor_replay_is_documented_limit(self):
        log=self.log();log.append({'event':'old'});log.close()
        old_log,old_anchor=Path(self.lp).read_bytes(),Path(self.ap).read_bytes()
        log=self.log();log.append({'event':'new'});log.close()
        Path(self.lp).write_bytes(old_log);Path(self.ap).write_bytes(old_anchor)
        self.assertTrue(audit.verify(self.lp,KEY,self.ap)['ok'],
                        'This intentionally documents the excluded rollback guarantee')

    def test_27_concurrent_calls_on_one_audit_writer_are_serialized(self):
        barrier=threading.Barrier(2)
        def clock():
            try:barrier.wait(timeout=.3)
            except threading.BrokenBarrierError:pass
            return NOW
        log=self.log();log.clock=clock;errors=[]
        def write():
            try:log.append({'event':'fictional concurrent request'})
            except Exception as exc:errors.append(type(exc).__name__)
        threads=[threading.Thread(target=write) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(3)
        self.assertFalse(any(t.is_alive() for t in threads));self.assertEqual(errors,[])
        log.close();self.assertTrue(audit.verify(self.lp,KEY,self.ap)['ok'])
        self.assertEqual(audit.verify(self.lp,KEY,self.ap)['entries'],2)

    def test_28_concurrent_nonce_consumers_allow_exactly_once(self):
        p=str(self.base/'nonce');authorities=[ApprovalAuthority(KEY,['human-1'],clock=lambda:NOW,ledger=NonceLedger(p)) for _ in range(2)]
        tok=authorities[0].issue('human-1',action());barrier=threading.Barrier(2);outcomes=[];real=os.fsync
        def sync(fd):
            try:barrier.wait(timeout=.3)
            except threading.BrokenBarrierError:pass
            return real(fd)
        def consume(authority):
            try:authority.verify(tok,action(),'agent-a');outcomes.append('ALLOW')
            except ApprovalError:outcomes.append('DENY')
        with patch('os.fsync',side_effect=sync):
            threads=[threading.Thread(target=consume,args=(auth,)) for auth in authorities]
            for t in threads:t.start()
            for t in threads:t.join(3)
        self.assertFalse(any(t.is_alive() for t in threads));self.assertEqual(sorted(outcomes),['ALLOW','DENY'])

    def test_29_component_wildcards_are_bounded(self):
        code='from agent_security_toolkit.pathpolicy import matches; print(matches("a*"*20+"b", "a"*100))'
        try:r=subprocess.run([sys.executable,'-B','-c',code],capture_output=True,text=True,timeout=2)
        except subprocess.TimeoutExpired:self.fail('100-character request with 20 stars exceeded a 2-second child budget')
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(r.stdout.strip(),'False')


if __name__=='__main__': unittest.main(verbosity=2)
