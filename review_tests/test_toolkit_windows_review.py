"""Toolkit-only Windows probes. Temporary fictional files; no elevation/settings.
Native exception hooks are controlled robustness tests, not demonstrated attacks.
"""
import ctypes, hashlib, os, tempfile, threading, unittest
from pathlib import Path
from ctypes import wintypes as wt
from unittest.mock import patch
from agent_security_toolkit.errors import AccessDenied

@unittest.skipUnless(os.name=='nt','Native Windows-only; no Linux simulation substituted')
class WindowsReview(unittest.TestCase):
    def setUp(self):
        from agent_security_toolkit.winfs import _win32, trusted_root, safe_read
        self.w,self.tr,self.sr=_win32,trusted_root,safe_read
        self.temp=tempfile.TemporaryDirectory(prefix='ast_native_review_');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'allowed';self.root.mkdir();self.file=self.root/'a.txt'
        self.data=b'FICTIONAL_APPROVED';self.file.write_bytes(self.data);self.sha=hashlib.sha256(self.data).hexdigest()
    def pin(self):
        pin=self.tr.TrustedRoot(str(self.root));self.addCleanup(pin.close);return pin
    def test_01_genuine_enrollment_control(self):
        p=self.pin();e=self.sr.enroll(p,{'a.txt':self.sha})
        self.assertEqual(self.sr.read_enrolled(p,e,'a.txt'),self.data)
    def test_02_casefold_historical_name_is_not_granted(self):
        self.file.rename(self.root/'ss.txt');p=self.pin();e=self.sr.enroll(p,{'ss.txt':self.sha})
        (self.root/'ss.txt').rename(self.root/'\u00df.txt');(self.root/'ss.txt').write_bytes(b'FICTIONAL_UNAPPROVED')
        with self.assertRaises((AccessDenied,ValueError)):self.sr.read_enrolled(p,e,'\u00df.txt')
        with self.assertRaises((AccessDenied,ValueError)):self.sr.read_enrolled(p,e,'ss.txt')
    def _native_output_fault(self,raise_after):
        p=self.pin();api=self.w.api();real=api.nt_open;captured=[]
        def wrapped(*args):
            result=real(*args)
            h=ctypes.cast(args[0],ctypes.POINTER(wt.HANDLE))[0]
            if result>=0 and h:
                captured.append(h)
                if raise_after:raise RuntimeError('controlled synthetic native-output exception')
                return -1073741790
            return result
        try:
            with patch.object(api,'nt_open',side_effect=wrapped):
                with self.assertRaises((RuntimeError,AccessDenied)):p.open_relative(p.validate(),'a.txt',False)
            validity=[]
            for h in captured:
                info=self.w.ByHandleInfo();validity.append(bool(api.info(h,ctypes.byref(info))))
            self.assertTrue(captured,'Real native acquisition did not occur')
            self.assertFalse(any(validity),'Acquired native output handle remains valid after failure')
        finally:
            # Close any reviewer-observed leak even when the assertion fails.
            for h in captured:
                info=self.w.ByHandleInfo()
                if api.info(h,ctypes.byref(info)):api.close(h)
    def test_03_native_output_exception_closes_handle(self):self._native_output_fault(True)
    def test_04_failed_status_with_output_closes_handle(self):self._native_output_fault(False)
    def test_05_content_mutation_denies(self):
        p=self.pin();e=self.sr.enroll(p,{'a.txt':self.sha});self.file.write_bytes(b'FICTIONAL_DIFFERENT')
        with self.assertRaises(AccessDenied):self.sr.read_enrolled(p,e,'a.txt')
    def test_06_orphaned_outside_origin_not_enrolled(self):
        outside=Path(self.temp.name)/'outside.txt';outside.write_bytes(b'FICTIONAL_OUTSIDE')
        p=self.pin();e=self.sr.enroll(p,{'a.txt':self.sha})
        os.link(outside,self.root/'alias.txt');outside.unlink()
        with self.assertRaises(AccessDenied):self.sr.read_enrolled(p,e,'alias.txt')
        self.assertEqual(self.sr.read_enrolled(p,e,'a.txt'),self.data)
    def test_07_orphan_replaces_enrolled_name_denied(self):
        outside=Path(self.temp.name)/'outside.txt';outside.write_bytes(self.data)
        p=self.pin();e=self.sr.enroll(p,{'a.txt':self.sha});self.file.unlink();os.link(outside,self.file);outside.unlink()
        with self.assertRaises(AccessDenied):self.sr.read_enrolled(p,e,'a.txt')
    def test_08_symlink_not_a_substitute_for_target_enrollment(self):
        p=self.pin();e=self.sr.enroll(p,{'a.txt':self.sha});alias=self.root/'alias.txt'
        try:os.symlink(self.file,alias)
        except OSError as exc:
            if getattr(exc,'winerror',None)==1314:self.skipTest('WinError 1314; no privilege/settings changes authorized')
            raise
        with self.assertRaises((AccessDenied,ValueError)):self.sr.read_enrolled(p,e,'alias.txt')
    def test_09_readfile_exception_cleanup(self):
        p=self.pin();e=self.sr.enroll(p,{'a.txt':self.sha});before=dict(self.tr.HANDLE_STATS)
        with patch.object(self.w.api(),'read',side_effect=RuntimeError('controlled ReadFile failure')):
            with self.assertRaises(RuntimeError):self.sr.read_enrolled(p,e,'a.txt')
        self.assertEqual(self.tr.HANDLE_STATS['opened']-before['opened'],self.tr.HANDLE_STATS['closed']-before['closed'])
    def test_10_concurrent_close_read_only_approved_or_denied(self):
        p=self.pin();e=self.sr.enroll(p,{'a.txt':self.sha});barrier=threading.Barrier(5);bad=[]
        def reader():
            barrier.wait()
            for _ in range(10):
                try:
                    if self.sr.read_enrolled(p,e,'a.txt')!=self.data:bad.append('unexpected bytes')
                except (AccessDenied,ValueError):pass
                except Exception as exc:bad.append(type(exc).__name__)
        threads=[threading.Thread(target=reader) for _ in range(4)]
        for t in threads:t.start()
        barrier.wait();p.close()
        for t in threads:t.join(5)
        self.assertFalse(any(t.is_alive() for t in threads),'bounded readers failed to finish');self.assertEqual(bad,[])
    def test_11_counter_control_is_not_process_attribution(self):
        before=dict(self.tr.HANDLE_STATS)
        for _ in range(30):
            with self.tr.TrustedRoot(str(self.root)) as p:
                e=self.sr.enroll(p,{'a.txt':self.sha});self.sr.read_enrolled(p,e,'a.txt')
        self.assertEqual(self.tr.HANDLE_STATS['opened']-before['opened'],self.tr.HANDLE_STATS['closed']-before['closed'])
        # This does not identify the historical unexplained process-wide +1.

if __name__=='__main__':unittest.main(verbosity=2)
