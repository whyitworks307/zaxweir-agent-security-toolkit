import copy, os, random, tempfile, shutil, unittest
from tests import _util
from agent_security_toolkit.policy import Policy, FORBIDDEN_TOOLS
from agent_security_toolkit.approval import ApprovalAuthority, NonceLedger, action_digest
from agent_security_toolkit.audit import AuditLog, verify
from agent_security_toolkit.gate import Gate
from agent_security_toolkit.errors import ConfigError, ApprovalError, AuditBusy, AuditError


class Clock:
    def __init__(self): self.t = 1_800_000_000
    def __call__(self): return self.t


class PolicyConfig(unittest.TestCase):
    def mk(self, **ch):
        d = copy.deepcopy(_util.BASE_POLICY); d.update(ch); return d

    def test_valid(self):
        Policy.from_dict(self.mk())

    def test_rejects(self):
        cases = [self.mk(arbitrary_shell=True), self.mk(arbitrary_shell="false"), self.mk(schema_version=2),
                 self.mk(approval_ttl_seconds=0), self.mk(approval_ttl_seconds=True), self.mk(unknown=1),
                 self.mk(approvers=["agent-a"]), self.mk(tools={}),
                 self.mk(tools={"shell.exec": {"risk": "low"}}),
                 self.mk(tools={"x.y": {"risk": "high", "requires_approval": False}}),
                 self.mk(tools={"x.y": {"risk": "extreme"}}), self.mk(tools={"BAD": {"risk": "low"}})]
        a = self.mk(); a["agents"]["agent-a"]["allowed_tools"] = ["nope.tool"]; cases.append(a)
        b = self.mk(); b["agents"]["agent-a"]["allowed_paths"] = ["../x"]; cases.append(b)
        c = self.mk(); c["agents"]["agent-a"]["allowed_tools"] = ["shell.exec"]; cases.append(c)
        for i, d in enumerate(cases):
            with self.subTest(i=i):
                with self.assertRaises(ConfigError):
                    Policy.from_dict(d)

    def test_authorize(self):
        p = Policy.from_dict(self.mk())
        self.assertTrue(p.authorize("agent-a", "docs.read", {"path": "ws/docs/x/y.txt"}).allowed)
        self.assertFalse(p.authorize("agent-b", "docs.read", {"path": "ws/docs/x/y.txt"}).allowed)
        for t in FORBIDDEN_TOOLS:
            d = p.authorize("agent-a", t, {})
            self.assertFalse(d.allowed); self.assertTrue(d.escalation_attempt)
        d = p.authorize("agent-b", "docs.write", {"path": "ws/docs/a.txt"})
        self.assertFalse(d.allowed); self.assertTrue(d.escalation_attempt)
        for k in ("run_as", "ELEVATE", "Impersonate", "bypass_approval"):
            d = p.authorize("agent-a", "docs.read", {"path": "ws/docs/a.txt", k: "x"})
            self.assertTrue(d.escalation_attempt, k)
        self.assertFalse(p.authorize("agent-a", "docs.read", {"path": "ws/docs/a.txt", "n": 1.0}).allowed)
        self.assertFalse(p.authorize("agent-a", "docs.read", {"path": "x" * 5000}).allowed)
        self.assertFalse(p.authorize(None, "docs.read", {}).allowed)
        self.assertFalse(p.authorize("agent-a", ["docs.read"], {}).allowed)


class Approvals(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.auth = ApprovalAuthority(os.urandom(32), {"human-1"}, 300, clock=self.clock)
        self.action = {"action_id": "a1", "agent": "agent-a", "tool": "docs.write", "args": {"path": "ws/docs/a"}}

    def test_valid_once(self):
        tok = self.auth.issue("human-1", self.action)
        self.assertEqual(self.auth.verify(tok, self.action, "agent-a"), "human-1")
        with self.assertRaises(ApprovalError):
            self.auth.verify(tok, self.action, "agent-a")

    def test_rejections(self):
        tok = self.auth.issue("human-1", self.action)
        variants = []
        for field, val in [("mac", "0" * 64), ("approver", "human-2"), ("expires", tok["expires"] + 1),
                           ("action_digest", "0" * 64), ("nonce", "zz"), ("v", 2)]:
            variants.append(dict(tok, **{field: val}))
        variants += ["{", None, [], {"v": 1}, dict(tok, extra=1)]
        for v in variants:
            with self.subTest(v=str(v)[:40]):
                with self.assertRaises(ApprovalError):
                    self.auth.verify(v, self.action, "agent-a")
        with self.assertRaises(ApprovalError):
            self.auth.verify(tok, dict(self.action, args={"path": "ws/docs/b"}), "agent-a")
        with self.assertRaises(ApprovalError):
            self.auth.verify(tok, self.action, "human-1")
        self.clock.t += 301
        with self.assertRaises(ApprovalError):
            self.auth.verify(tok, self.action, "agent-a")

    def test_other_key(self):
        other = ApprovalAuthority(os.urandom(32), {"human-1"}, 300, clock=self.clock)
        with self.assertRaises(ApprovalError):
            self.auth.verify(other.issue("human-1", self.action), self.action, "agent-a")

    def test_issue_refuses_unknown(self):
        with self.assertRaises((ApprovalError, ConfigError)):
            self.auth.issue("nobody", self.action)

    def test_persistent_ledger(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        key = os.urandom(32); path = os.path.join(d, "n.txt")
        a1 = ApprovalAuthority(key, {"human-1"}, 300, clock=self.clock, ledger=NonceLedger(path))
        tok = a1.issue("human-1", self.action)
        a1.verify(tok, self.action, "agent-a")
        a2 = ApprovalAuthority(key, {"human-1"}, 300, clock=self.clock, ledger=NonceLedger(path))
        with self.assertRaises(ApprovalError):
            a2.verify(tok, self.action, "agent-a")
        with open(path, "ab") as fh:
            fh.write(b"garbage\n")
        with self.assertRaises(ApprovalError):
            NonceLedger(path)

    def test_short_key(self):
        with self.assertRaises(ConfigError):
            ApprovalAuthority(b"short", {"h"})

    def test_digest_binding(self):
        self.assertNotEqual(action_digest(self.action),
                            action_digest(dict(self.action, args={"path": "ws/docs/a", "x": 1})))


class Audit(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d)
        self.key = os.urandom(32)
        self.lp, self.ap = os.path.join(self.d, "a.jsonl"), os.path.join(self.d, "a.anchor")

    def fill(self, n=5):
        with AuditLog(self.lp, self.ap, self.key) as log:
            for i in range(n):
                log.append({"decision": "DENY", "i": i})

    def test_roundtrip_and_reopen(self):
        self.fill(); self.fill()
        r = verify(self.lp, self.key, self.ap)
        self.assertTrue(r["ok"]); self.assertEqual(r["entries"], 10)

    def test_wrong_key(self):
        self.fill()
        self.assertFalse(verify(self.lp, os.urandom(32), self.ap)["ok"])

    def test_single_writer(self):
        log = AuditLog(self.lp, self.ap, self.key)
        try:
            with self.assertRaises(AuditBusy):
                AuditLog(self.lp, self.ap, self.key)
        finally:
            log.close()

    def test_refuse_append_to_tampered(self):
        self.fill()
        with open(self.lp, "r+b") as fh:
            data = fh.read(); fh.seek(0); fh.write(data.replace(b"DENY", b"ALLW", 1))
        with self.assertRaises(AuditError):
            AuditLog(self.lp, self.ap, self.key)

    def test_missing_anchor_detected(self):
        self.fill(); os.unlink(self.ap)
        self.assertFalse(verify(self.lp, self.key, self.ap)["ok"])

    def test_documented_limit_consistent_rollback(self):
        """KNOWN LIMITATION: restoring an older log AND its matching anchor is NOT detected."""
        self.fill(3)
        with open(self.lp, "rb") as f1, open(self.ap, "rb") as f2:
            old_l, old_a = f1.read(), f2.read()
        self.fill(2)
        with open(self.lp, "wb") as f1, open(self.ap, "wb") as f2:
            f1.write(old_l); f2.write(old_a)
        self.assertTrue(verify(self.lp, self.key, self.ap)["ok"])  # documents the gap, does not hide it


class GateTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d)
        self.clock = Clock()
        self.policy = Policy.from_dict(copy.deepcopy(_util.BASE_POLICY))
        self.auth = ApprovalAuthority(os.urandom(32), self.policy.approvers, 300, clock=self.clock)
        self.key = os.urandom(32)
        self.lp, self.ap = os.path.join(self.d, "a.jsonl"), os.path.join(self.d, "a.anchor")
        self.log = AuditLog(self.lp, self.ap, self.key, clock=self.clock)
        self.addCleanup(self.log.close)
        self.gate = Gate(self.policy, self.auth, self.log)

    def test_flow(self):
        g = self.gate
        self.assertTrue(g.submit({"action_id": "1", "agent": "agent-a", "tool": "docs.read",
                                  "args": {"path": "ws/docs/a.txt"}})["allowed"])
        self.assertFalse(g.submit({"action_id": "1", "agent": "agent-a", "tool": "docs.read",
                                   "args": {"path": "ws/docs/a.txt"}})["allowed"])
        act = {"action_id": "2", "agent": "agent-a", "tool": "docs.write", "args": {"path": "ws/docs/a.txt"}}
        self.assertFalse(g.submit(dict(act))["allowed"])
        act["action_id"] = "3"
        tok = self.auth.issue("human-1", act)
        self.assertTrue(g.submit(dict(act, approval=tok))["allowed"])
        r = verify(self.lp, self.key, self.ap)
        self.assertTrue(r["ok"]); self.assertEqual(r["entries"], 4)

    def test_audit_failure_denies(self):
        class Broken:
            def append(self, e): raise OSError("disk full")
        g = Gate(self.policy, self.auth, Broken())
        r = g.submit({"action_id": "1", "agent": "agent-a", "tool": "docs.read", "args": {"path": "ws/docs/a.txt"}})
        self.assertFalse(r["allowed"])

    def test_randomized_requests_never_allow_unsafe(self):
        rng = random.Random(_util.SEED)
        agents = ["agent-a", "agent-b", "agent-c", "human-1", None, 1]
        tools = ["docs.read", "docs.write", "mail.send_draft", "shell.exec", "x.y", None]
        paths = ["ws/docs/a.txt", "ws/docs/sub/b.txt", "../x", "C:\\x", "ws/other/a.txt", "WS/docs/a.txt", 5]
        for i in range(_util.FUZZ_N):
            req = {"action_id": "r%d" % i, "agent": rng.choice(agents), "tool": rng.choice(tools),
                   "args": {"path": rng.choice(paths)}}
            if rng.random() < 0.2:
                req["args"][rng.choice(["run_as", "x", "elevate"])] = "y"
            if rng.random() < 0.1:
                req[rng.choice(["approval", "zzz"])] = rng.choice([None, "{", {"v": 1}])
            out = self.gate.submit(req)
            if out["allowed"]:
                self.assertIn(req["agent"], ("agent-a", "agent-b"))
                self.assertEqual(req["tool"], "docs.read")
                p = req["args"]["path"]
                self.assertTrue(p.startswith("ws/docs/"), req)
                self.assertFalse({"run_as", "elevate"} & set(req["args"]), req)
                if req["agent"] == "agent-b":
                    self.assertNotIn("/", p[len("ws/docs/"):])
        self.assertTrue(verify(self.lp, self.key, self.ap)["ok"])
