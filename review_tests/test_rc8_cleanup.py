"""rc8 cleanup regressions: modeled failures and real-handle reported faults.

The Windows tests close a real handle successfully, then inject a reporting
failure. They do not claim to induce an actual OS CloseHandle failure.
"""
import ctypes
import hashlib
import os
from pathlib import Path
import tempfile
import importlib.util
import tomllib
import types
import unittest
import zipfile
from unittest.mock import patch

from agent_security_toolkit.errors import AccessDenied
from agent_security_toolkit import audit
from agent_security_toolkit.errors import AuditError
from agent_security_toolkit.winfs import safe_read as sr


class CleanupFailures(unittest.TestCase):
    def invoke(self, failures=(), primary=None, malformed_cleanup_notes=False):
        data = b"SYNTHETIC_APPROVED"
        info = types.SimpleNamespace(nFileSizeHigh=0, nFileSizeLow=len(data), nNumberOfLinks=1)
        attempted = []
        supplied = {}
        reads = []
        class Pin:
            final = r"c:\synthetic"
            def validate(self): return 1
            def open_relative(self, parent, name, directory):
                return {"one": 2, "two": 3, "leaf": 4}[name], info
        def read(handle, buffer, count, got, unused):
            if primary is not None:
                raise primary
            if not reads:
                ctypes.memmove(buffer, data, len(data))
                got._obj.value = len(data)
            else:
                got._obj.value = 0
            reads.append(1)
            return True
        def release(handle):
            attempted.append(handle)
            if handle in failures:
                error = AccessDenied("Synthetic cleanup failure %d" % handle)
                if malformed_cleanup_notes:
                    error.__notes__ = 0
                supplied[handle] = error
                raise error
        returned = error = None
        with patch.object(sr.w, "api", return_value=types.SimpleNamespace(read=read)), \
             patch.object(sr, "identity_of", return_value=(1, 99)), \
             patch.object(sr, "final_path", return_value=r"c:\synthetic\one\two\leaf"), \
             patch.object(sr, "query", return_value=info), \
             patch.object(sr, "release", side_effect=release):
            try:
                returned = sr._walk_and_read(Pin(), ("one", "two", "leaf"), 64)
            except BaseException as exc:
                error = exc
        self.assertEqual(attempted, [4, 3, 2])
        return returned, error, supplied, data

    def test_normal_read_and_reverse_cleanup(self):
        returned, error, _, data = self.invoke()
        self.assertIsNone(error)
        self.assertEqual(returned, (data, (1, 99)))

    def test_first_close_failure_attempts_all_handles(self):
        returned, error, supplied, _ = self.invoke((4,))
        self.assertIsNone(returned)
        self.assertIs(error, supplied[4])

    def test_middle_close_failure_attempts_all_handles(self):
        returned, error, supplied, _ = self.invoke((3,))
        self.assertIsNone(returned)
        self.assertIs(error, supplied[3])

    def test_last_close_failure_denies_successful_read(self):
        returned, error, supplied, _ = self.invoke((2,))
        self.assertIsNone(returned)
        self.assertIs(error, supplied[2])

    def test_multiple_close_failures_preserve_first(self):
        returned, error, supplied, _ = self.invoke((4, 3, 2))
        self.assertIsNone(returned)
        self.assertIs(error, supplied[4])
        self.assertIn("2 additional", error.__notes__[0])

    def test_primary_security_denial_is_not_masked(self):
        primary = AccessDenied("Synthetic original security denial")
        returned, error, _, _ = self.invoke((4, 2), primary)
        self.assertIsNone(returned)
        self.assertIs(error, primary)
        self.assertIn("2 handle(s)", error.__notes__[0])

    def test_primary_os_error_is_not_masked(self):
        primary = OSError("Synthetic read failure")
        returned, error, _, _ = self.invoke((4, 3), primary)
        self.assertIsNone(returned)
        self.assertIs(error, primary)

    def test_primary_base_exception_is_not_masked(self):
        primary = KeyboardInterrupt("Synthetic interruption")
        returned, error, _, _ = self.invoke((4, 3, 2), primary)
        self.assertIsNone(returned)
        self.assertIs(error, primary)

    def test_primary_error_without_cleanup_failure_preserved(self):
        primary = RuntimeError("Synthetic original failure")
        returned, error, _, _ = self.invoke((), primary)
        self.assertIsNone(returned)
        self.assertIs(error, primary)

    def test_existing_malformed_notes_do_not_mask_primary(self):
        primary = AccessDenied("Synthetic original denial")
        primary.__notes__ = 0
        returned, error, _, _ = self.invoke((4, 3), primary)
        self.assertIsNone(returned)
        self.assertIs(error, primary)

    def test_existing_malformed_notes_do_not_mask_first_close_fault(self):
        returned, error, supplied, _ = self.invoke((4, 3), malformed_cleanup_notes=True)
        self.assertIsNone(returned)
        self.assertIs(error, supplied[4])


@unittest.skipUnless(os.name == "nt", "real Windows handles required")
class WindowsReportedCleanupFailures(unittest.TestCase):
    def check_fault(self, positions, primary_failure=False):
        from agent_security_toolkit.winfs.trusted_root import TrustedRoot, HANDLE_STATS
        before = dict(HANDLE_STATS)
        attempted = []
        release = sr.release
        with tempfile.TemporaryDirectory(prefix="ast_rc8_cleanup_") as d:
            p = Path(d) / "one" / "two" / "leaf"
            p.parent.mkdir(parents=True)
            data = b"SYNTHETIC_APPROVED"
            p.write_bytes(data)
            with TrustedRoot(d) as pin:
                enrollment = sr.enroll(pin, {"one/two/leaf": hashlib.sha256(data).hexdigest()})
                def reported_fault(handle):
                    attempted.append(handle)
                    release(handle)  # actual close succeeds; only its report is fault-injected
                    if len(attempted) in positions:
                        raise AccessDenied("Synthetic reported cleanup failure")
                with patch.object(sr, "release", side_effect=reported_fault):
                    if primary_failure:
                        with patch.object(sr, "final_path", side_effect=AccessDenied("Synthetic original denial")):
                            with self.assertRaisesRegex(AccessDenied, "Synthetic original denial"):
                                sr.read_enrolled(pin, enrollment, "one/two/leaf")
                    else:
                        with self.assertRaisesRegex(AccessDenied, "Synthetic reported cleanup failure"):
                            sr.read_enrolled(pin, enrollment, "one/two/leaf")
                self.assertEqual(len(attempted), 3)
        self.assertEqual(HANDLE_STATS["opened"] - before["opened"], HANDLE_STATS["closed"] - before["closed"])

    def test_first_reported_close_failure(self): self.check_fault({1})
    def test_subsequent_reported_close_failure(self): self.check_fault({2})
    def test_multiple_reported_close_failures_preserve_denial(self): self.check_fault({1, 3}, True)


class ReleaseMetadata(unittest.TestCase):
    def setUp(self):
        self.root = Path(os.environ.get('REVIEW_SOURCE_ROOT', Path(__file__).resolve().parents[1]))

    def test_approved_notice_and_canonical_license(self):
        self.assertEqual(hashlib.sha256((self.root / 'LICENSE').read_bytes()).hexdigest(),
                         'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30')
        self.assertIn('Copyright 2026 Christopher Wright', (self.root / 'NOTICE').read_text())
        for obsolete in ('NOTICE-DRAFT', 'LICENSE-PROPOSED', 'PROPOSED_LICENSE.md'):
            self.assertFalse((self.root / obsolete).exists(), obsolete)
        project = tomllib.loads((self.root / 'pyproject.toml').read_text())['project']
        self.assertEqual(project['license'], {'file': 'LICENSE'})
        self.assertIn('License :: OSI Approved :: Apache Software License', project['classifiers'])

    def test_verified_private_contact_and_daily_monitoring(self):
        text = (self.root / 'SECURITY.md').read_text()
        self.assertIn('founder@zaxweir.com', text)
        self.assertIn('every day', text)
        self.assertNotIn('[BLOCKER:', text)
        self.assertIn('inherited', text.lower())

    def test_wheel_carries_license_notice_and_metadata(self):
        spec = importlib.util.spec_from_file_location('rc8_wheel', self.root / 'tools/build_wheel.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix='ast_rc8_wheel_') as d:
            path = module.main(d)
            with zipfile.ZipFile(path) as z:
                di = 'agent_security_toolkit-' + module.version() + '.dist-info/'
                self.assertIn('License: Apache-2.0', z.read(di + 'METADATA').decode())
                self.assertEqual(z.read(di + 'LICENSE'), (self.root / 'LICENSE').read_bytes())
                self.assertEqual(z.read(di + 'NOTICE'), (self.root / 'NOTICE').read_bytes())


class AuditAtomicWrites(unittest.TestCase):
    def test_legacy_temp_collision_cannot_split_log_anchor(self):
        with tempfile.TemporaryDirectory(prefix='ast_rc8_atomic_') as d:
            log_path, anchor = str(Path(d) / 'log'), str(Path(d) / 'anchor')
            key = b'SYNTHETIC-TEST-KEY-ONLY-' * 2
            with audit.AuditLog(log_path, anchor, key) as log:
                stale = Path(anchor + '.tmp-%d' % os.getpid())
                stale.write_bytes(b'SYNTHETIC_PREEXISTING_FILE')
                failure = None
                try:
                    log.append({'decision': 'DENY', 'fixture': 'synthetic'})
                except OSError as exc:
                    failure = type(exc).__name__
                result = audit.verify(log_path, key, anchor)
                self.assertIsNone(failure, {'exception': failure, 'verifier': result})
                self.assertTrue(result['ok'], result)
                self.assertEqual(result['entries'], 1)
                self.assertEqual(stale.read_bytes(), b'SYNTHETIC_PREEXISTING_FILE')

    def atomic_fault(self, api, error):
        with tempfile.TemporaryDirectory(prefix='ast_rc8_atomic_') as d:
            path = Path(d) / 'anchor'
            path.write_bytes(b'SYNTHETIC_OLD_TARGET')
            kwargs = {'return_value': error} if isinstance(error, int) else {'side_effect': error}
            with patch.object(audit.os, api, **kwargs):
                with self.assertRaises((AuditError, OSError)):
                    audit._write_atomic(str(path), b'SYNTHETIC_NEW_TARGET')
            self.assertEqual(path.read_bytes(), b'SYNTHETIC_OLD_TARGET')
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()), ['anchor'])

    def test_short_write_keeps_target_and_cleans_owned_temp(self): self.atomic_fault('write', 0)
    def test_fsync_fault_keeps_target_and_cleans_owned_temp(self): self.atomic_fault('fsync', OSError('Synthetic fsync failure'))
    def test_replace_fault_keeps_target_and_cleans_owned_temp(self): self.atomic_fault('replace', PermissionError('Synthetic replace failure'))

    def test_normal_atomic_updates_leave_no_owned_temps(self):
        with tempfile.TemporaryDirectory(prefix='ast_rc8_atomic_') as d:
            path = Path(d) / 'anchor'
            for i in range(20): audit._write_atomic(str(path), ('SYNTHETIC_%d' % i).encode())
            self.assertEqual(path.read_bytes(), b'SYNTHETIC_19')
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()), ['anchor'])
