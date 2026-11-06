"""Hygiene: shipped sources/configs contain no forbidden material or project-coupling terms."""
import os, re, unittest
from tests import _util

FORBIDDEN = [rb"(?i)relay", rb"(?i)\bjev\b", rb"(?i)broker", rb"(?i)crypto\.com", rb"(?i)ngrok",
             rb"(?i)c:\\\\users\\\\", rb"(?i)parad", rb"(?i)BEGIN [A-Z ]*PRIVATE KEY", rb"(?i)api[_-]?key\s*[:=]",
             rb"AKIA[0-9A-Z]{16}", rb"(?i)password\s*[:=]\s*\S", rb"ghp_[A-Za-z0-9]{20,}", rb"(?i)zaxweir"]


class Hygiene(unittest.TestCase):
    def test_no_forbidden_terms(self):
        hits = []
        for top in ("src", "configs", "tests"):
            for d, _, files in os.walk(os.path.join(_util.ROOT, top)):
                if "__pycache__" in d:
                    continue
                for f in files:
                    p = os.path.join(d, f)
                    if f == "test_packaging.py":
                        continue
                    with open(p, "rb") as fh:
                        data = fh.read()
                    for pat in FORBIDDEN:
                        if re.search(pat, data):
                            hits.append((os.path.relpath(p, _util.ROOT), pat.decode()))
        self.assertEqual(hits, [])

    def test_stdlib_only(self):
        import ast, sys
        std = set(sys.stdlib_module_names)
        for d, _, files in os.walk(os.path.join(_util.SRC, "agent_security_toolkit")):
            for f in files:
                if f.endswith(".py"):
                    with open(os.path.join(d, f), encoding="utf-8") as fh:
                        tree = ast.parse(fh.read())
                    for n in ast.walk(tree):
                        names = [a.name for a in n.names] if isinstance(n, ast.Import) else (
                            [n.module] if isinstance(n, ast.ImportFrom) and n.level == 0 and n.module else [])
                        for m in names:
                            self.assertIn(m.split(".")[0], std, (f, m))
