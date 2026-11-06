import glob, json, os, shutil, subprocess, sys, tempfile, unittest
from tests import _util

CFG = os.path.join(_util.ROOT, "configs", "examples", "baseline_scenarios.json")


def run(*args):
    env = dict(os.environ, PYTHONPATH=_util.SRC)
    return subprocess.run([sys.executable, "-m", "agent_security_toolkit", *args], capture_output=True,
                          text=True, env=env, timeout=600)


class Cli(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, True)

    def test_version(self):
        r = run("version"); self.assertEqual(r.returncode, 0); self.assertTrue(r.stdout.strip())

    def test_run_example(self):
        r = run("run", CFG, "--out", self.d)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        js = glob.glob(os.path.join(self.d, "*.json")); md = glob.glob(os.path.join(self.d, "*.md"))
        self.assertEqual((len(js), len(md)), (1, 1))
        with open(js[0], encoding="utf-8") as fh:
            rep = json.load(fh)
        self.assertTrue(rep["passed"]); self.assertIn("BUILDER-VERIFIED ONLY", rep["verification_label"])
        self.assertEqual(len(rep["results"]["audit_tamper"]), 7)
        with open(md[0], encoding="utf-8") as fh:
            self.assertIn("Overall: **PASS**", fh.read())
        with open(js[0], "rb") as fh:
            blob = fh.read()
        self.assertNotIn(b"key", blob.lower().replace(b"keys", b""))  # no key material in reports

    def test_failing_expectation_exit1(self):
        with open(CFG, encoding="utf-8") as fh:
            cfg = json.load(fh)
        cfg["scenarios"][0]["steps"][0]["expect"] = "deny"
        p = os.path.join(self.d, "c.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
        self.assertEqual(run("run", p, "--out", self.d).returncode, 1)

    def test_invalid_configs_exit2(self):
        cases = ['{"schema_version": 1, "schema_version": 1}', "not json", "{}",
                 json.dumps({"schema_version": 1, "name": "x", "scenarios": [], "policy": {}})]
        with open(CFG, encoding="utf-8") as fh:
            cfg = json.load(fh)
        cfg["policy"]["arbitrary_shell"] = True
        cases.append(json.dumps(cfg))
        for i, c in enumerate(cases):
            p = os.path.join(self.d, "bad%d.json" % i)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(c)
            with self.subTest(i=i):
                r = run("validate", p)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertNotIn("Traceback", r.stderr)

    def test_missing_file_exit2(self):
        self.assertEqual(run("validate", os.path.join(self.d, "nope.json")).returncode, 2)

    def test_keygen_and_verify_audit(self):
        k = os.path.join(self.d, "k.bin")
        self.assertEqual(run("keygen", k).returncode, 0)
        self.assertEqual(run("keygen", k).returncode, 2)  # never overwrite
        sys.path.insert(0, _util.SRC)
        from agent_security_toolkit.audit import AuditLog
        with open(k, "rb") as fh:
            key = fh.read()
        lp, ap = os.path.join(self.d, "a.jsonl"), os.path.join(self.d, "a.anchor")
        with AuditLog(lp, ap, key) as log:
            log.append({"decision": "DENY"})
        self.assertEqual(run("verify-audit", lp, ap, "--key-file", k).returncode, 0)
        with open(lp, "ab") as fh:
            fh.write(b'{"seq": 2}\n')
        self.assertEqual(run("verify-audit", lp, ap, "--key-file", k).returncode, 1)

    @unittest.skipIf(os.name == "nt", "non-Windows behaviour")
    def test_fsprobe_non_windows(self):
        self.assertEqual(run("fsprobe", "--out", self.d).returncode, 3)

    @unittest.skipUnless(os.name == "nt", "native Windows probe")
    def test_fsprobe_windows(self):
        r = run("fsprobe", "--out", self.d, "--iterations", "200")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
