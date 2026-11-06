"""Native Windows filesystem tests (skipped elsewhere)."""
import hashlib, os, shutil, tempfile, unittest
from tests import _util  # noqa
from agent_security_toolkit.errors import AccessDenied

WIN = os.name == "nt"


@unittest.skipUnless(WIN, "Windows-only")
class WinFs(unittest.TestCase):
    def setUp(self):
        from agent_security_toolkit.winfs import trusted_root
        self.tr = trusted_root
        self.d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.d, True)
        self.root = os.path.join(self.d, "root"); os.makedirs(os.path.join(self.root, "docs"))
        self.data = b"synthetic approved"
        with open(os.path.join(self.root, "docs", "a.txt"), "wb") as fh:
            fh.write(self.data)
        self.sha = hashlib.sha256(self.data).hexdigest()

    def test_enroll_and_read(self):
        from agent_security_toolkit.winfs.safe_read import enroll, read_enrolled
        with self.tr.TrustedRoot(self.root) as pin:
            e = enroll(pin, {"docs/a.txt": self.sha})
            self.assertEqual(read_enrolled(pin, e, "docs/a.txt"), self.data)
            self.assertEqual(read_enrolled(pin, e, "docs\\a.txt"), self.data)
            for bad in ["DOCS/a.txt", "docs/A.TXT", "../root/docs/a.txt", "docs/a.txt:x"]:
                with self.assertRaises((AccessDenied, ValueError)):
                    read_enrolled(pin, e, bad)

    def test_enroll_hash_mismatch(self):
        from agent_security_toolkit.winfs.safe_read import enroll
        with self.tr.TrustedRoot(self.root) as pin:
            with self.assertRaises(AccessDenied):
                enroll(pin, {"docs/a.txt": "0" * 64})

    def test_enrollment_bound_to_pin(self):
        from agent_security_toolkit.winfs.safe_read import enroll, read_enrolled
        with self.tr.TrustedRoot(self.root) as p1, self.tr.TrustedRoot(self.root) as p2:
            e = enroll(p1, {"docs/a.txt": self.sha})
            with self.assertRaises(AccessDenied):
                read_enrolled(p2, e, "docs/a.txt")

    def test_closed_pin_refuses(self):
        from agent_security_toolkit.winfs.safe_read import enroll, read_enrolled
        pin = self.tr.TrustedRoot(self.root)
        e = enroll(pin, {"docs/a.txt": self.sha})
        pin.close()
        with self.assertRaises(Exception):
            read_enrolled(pin, e, "docs/a.txt")

    def test_module_handle_balance(self):
        """Per-module accounting (replaces process-wide handle counting, see R04 flake)."""
        from agent_security_toolkit.winfs.safe_read import enroll, read_enrolled
        start = dict(self.tr.HANDLE_STATS)
        for _ in range(50):
            with self.tr.TrustedRoot(self.root) as pin:
                e = enroll(pin, {"docs/a.txt": self.sha})
                read_enrolled(pin, e, "docs/a.txt")
                for bad in ["nope.txt", "docs", "docs/a.txt"]:
                    try:
                        read_enrolled(pin, e, bad, max_bytes=1)
                    except (AccessDenied, ValueError):
                        pass
        opened = self.tr.HANDLE_STATS["opened"] - start["opened"]
        closed = self.tr.HANDLE_STATS["closed"] - start["closed"]
        self.assertGreater(opened, 0)
        self.assertEqual(opened, closed)

    def test_fsprobe_all_pass(self):
        from agent_security_toolkit.fsprobe import run_probe
        results = run_probe(race_iterations=150)
        bad = [r for r in results if r["outcome"] in ("LEAKED", "FAILED")
               or (not r["passed"] and r["outcome"] != "SKIPPED")]
        self.assertEqual(bad, [])
        ids = {r["id"] for r in results}
        for must in ("orphaned_hardlink_unenrolled", "enrolled_name_replaced_by_orphaned_link",
                     "junction_to_outside", "hardlink_multi_link", "toctou_inplace_content_race", "enrolled_parent_replaced_by_junction", "enrolled_file_gains_hardlink",
                     "root_boundary_swap_race", "native_handle_balance"):
            self.assertIn(must, ids)
