import random, unittest
from tests import _util
from agent_security_toolkit import pathpolicy as pp
from agent_security_toolkit.errors import AccessDenied

BAD = ["", "/", "\\", "/etc/passwd", "C:\\x", "C:x", "c:/x", "\\\\srv\\share", "\\\\?\\C:\\x", "\\\\.\\PhysicalDrive0",
       "..", "a/../b", "./a", "a//b", "a/./b", "a:b", "a/b::$DATA", "CON", "con.txt", "a/NUL", "LPT1.log", "COM\u00b9",
       "a.", "a ", "a\x00b", "a\x1fb", "a\u202eb", "a\u200bb", "a*b", "a?b", "a<b", 'a"b', "a|b", "PROGRA~1",
       "docs/LONG_D~1.TXT", "a/" * 40 + "x", "x" * 256, "\ud800"]
GOOD = ["a", "a/b.txt", "a\\b.txt", "docs/readme.md", "D\u00e9j\u00e0/vu.txt", "x" * 255, "a~b", "con1", "COMX"]


class PathPolicy(unittest.TestCase):
    def test_bad(self):
        for p in BAD:
            with self.subTest(p=repr(p)):
                with self.assertRaises(AccessDenied):
                    pp.components(p)

    def test_good(self):
        for p in GOOD:
            with self.subTest(p=p):
                self.assertTrue(pp.components(p))

    def test_separator_equivalence(self):
        self.assertEqual(pp.components("a\\b"), pp.components("a/b"))

    def test_non_string(self):
        for p in [None, b"a", 1, ["a"]]:
            with self.assertRaises((AccessDenied, TypeError, ValueError)):
                pp.components(p)

    def test_matches(self):
        self.assertTrue(pp.matches("ws/docs/**", "ws/docs/a/b.txt"))
        self.assertTrue(pp.matches("ws/docs/*.txt", "ws/docs/a.txt"))
        self.assertFalse(pp.matches("ws/docs/*.txt", "ws/docs/a/b.txt"))
        self.assertFalse(pp.matches("ws/docs/*.txt", "WS/docs/a.txt"))
        self.assertFalse(pp.matches("ws/docs/**", "ws/docsx/a"))
        with self.assertRaises(AccessDenied):
            pp.matches("ws/docs/**", "ws/docs/../x")

    def test_randomized_never_escapes(self):
        """Random component soup: any accepted path must have only safe components."""
        rng = random.Random(_util.SEED)
        alphabet = ["a", "B", ".", "..", "/", "\\", ":", "~", " ", "\x00", "\u202e", "C:", "CON", "$", "*",
                    "\u00e9", "1", "-", "_", "NUL", "\\\\", "?", "\ud800", "\u200b", "\t"]
        accepted = 0
        for _ in range(_util.FUZZ_N):
            s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12)))
            try:
                parts = pp.components(s)
            except AccessDenied:
                continue
            accepted += 1
            for c in parts:
                self.assertNotIn(c, ("", ".", ".."), s)
                self.assertFalse(any(ch in c for ch in ':*?"<>|\x00/\\'), repr(s))
                self.assertFalse(c.endswith((".", " ")), repr(s))
            joined = "/".join(parts)
            self.assertEqual(pp.components(joined), parts)
        self.assertGreater(accepted, 0)
