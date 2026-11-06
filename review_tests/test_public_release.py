"""Bounded synthetic release validation and command-search regression tests."""
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import types
import unittest
import warnings
import zipfile
from unittest.mock import patch
from agent_security_toolkit import fsprobe

SOURCE = pathlib.Path(os.environ['REVIEW_SOURCE_ROOT'])
spec = importlib.util.spec_from_file_location('release_verifier', SOURCE/'tools/verify_release.py')
v = importlib.util.module_from_spec(spec);spec.loader.exec_module(v)


def fixture(extra=None, manifest=None, mode=None):
    files = {'README.md': b'Synthetic source'}
    if extra:files.update(extra)
    hashes = {p: hashlib.sha256(b).hexdigest() for p,b in files.items()}
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        for p,b in files.items():
            name=v.ROOT+'/'+p
            if mode:
                i=zipfile.ZipInfo(name);i.external_attr=mode<<16;z.writestr(i,b)
            else:z.writestr(name,b)
        z.writestr(v.ROOT+'/SOURCE_MANIFEST.json',json.dumps(hashes if manifest is None else manifest))
    return out.getvalue()


class ReleaseTests(unittest.TestCase):
    def check(self,b):return v.verify_bytes(b,hashlib.sha256(b).hexdigest())
    def test_01_good_synthetic_archive(self):self.assertTrue(self.check(fixture())['ok'])
    def test_02_wrong_external_digest_rejected(self):
        with self.assertRaises(v.VerificationError):v.verify_bytes(fixture(),'0'*64)
    def test_03_tampered_archive_rejected(self):
        b=fixture()
        with self.assertRaises(v.VerificationError):v.verify_bytes(b+b'TAMPER',hashlib.sha256(b).hexdigest())
    def test_04_traversal_rejected_before_extraction(self):
        with self.assertRaises(v.VerificationError):self.check(fixture({'../outside':b'synthetic'}))
    def test_05_backslash_or_drive_path_rejected(self):
        for p in [r'..\outside',r'C:\outside','a//b','/absolute','x/CON.txt']:
            with self.subTest(p=p),self.assertRaises(v.VerificationError):self.check(fixture({p:b'synthetic'}))
    def test_06_case_collision_rejected(self):
        with self.assertRaises(v.VerificationError):self.check(fixture({'readme.md':b'synthetic'}))
    def test_07_symlink_entry_rejected(self):
        with self.assertRaises(v.VerificationError):self.check(fixture(mode=stat.S_IFLNK|0o777))
    def test_08_manifest_missing_member_rejected(self):
        with self.assertRaises(v.VerificationError):self.check(fixture(manifest={}))
    def test_09_manifest_wrong_digest_rejected(self):
        with self.assertRaises(v.VerificationError):self.check(fixture(manifest={'README.md':'0'*64}))
    def test_10_duplicate_member_rejected(self):
        b=io.BytesIO(fixture())
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(b,'a') as z:z.writestr(v.ROOT+'/README.md',b'synthetic duplicate')
        with self.assertRaises(v.VerificationError):self.check(b.getvalue())
    def test_11_duplicate_manifest_keys_rejected(self):
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            z.writestr(v.ROOT+'/README.md',b'Synthetic source')
            digest=hashlib.sha256(b'Synthetic source').hexdigest()
            z.writestr(v.ROOT+'/SOURCE_MANIFEST.json','{"README.md":"'+digest+'","README.md":"'+digest+'"}')
        with self.assertRaises(v.VerificationError):self.check(out.getvalue())
    def test_12_member_count_bound(self):
        with patch.object(v,'MAX_FILES',1),self.assertRaises(v.VerificationError):self.check(fixture())
    def test_13_expanded_size_bound(self):
        with patch.object(v,'MAX_TOTAL',1),self.assertRaises(v.VerificationError):self.check(fixture())
    def test_14_invalid_zip_rejected(self):
        with self.assertRaises(v.VerificationError):self.check(b'not a zip')
    def test_15_archive_size_bound(self):
        with patch.object(v,'MAX_ARCHIVE',1),self.assertRaises(v.VerificationError):self.check(fixture())
    def test_20_corrupt_member_crc_rejected(self):
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w',zipfile.ZIP_STORED) as z:
            z.writestr(v.ROOT+'/README.md',b'Synthetic source')
            z.writestr(v.ROOT+'/SOURCE_MANIFEST.json',json.dumps({'README.md':hashlib.sha256(b'Synthetic source').hexdigest()}))
        b=bytearray(out.getvalue())
        with zipfile.ZipFile(io.BytesIO(b)) as z:i=z.infolist()[0]
        offset=i.header_offset+30+len(i.filename.encode())+len(i.extra)
        b[offset]^=1
        with self.assertRaises(v.VerificationError):self.check(bytes(b))
    def test_23_invalid_deflate_stream_rejected(self):
        b=bytearray(fixture())
        with zipfile.ZipFile(io.BytesIO(b)) as z:i=z.infolist()[0]
        offset=i.header_offset+30+len(i.filename.encode())+len(i.extra)
        b[offset]=7  # Reserved DEFLATE block type; not a harmless final-block-bit change.
        with self.assertRaises(v.VerificationError):self.check(bytes(b))
    def test_16_system_directory_failure_prevents_dispatch(self):
        fn=types.SimpleNamespace()
        class Api:
            def __call__(self,*args):return 0
        fn.GetSystemDirectoryW=Api()
        with patch.object(fsprobe.ctypes,'WinDLL',return_value=fn,create=True),patch.object(fsprobe.subprocess,'run') as dispatch:
            with self.assertRaises(RuntimeError):fsprobe._junction('synthetic-link','synthetic-target')
            dispatch.assert_not_called()
    def test_17_system_directory_overflow_prevents_dispatch(self):
        class Api:
            def __call__(self,*args):return 40000
        with patch.object(fsprobe.ctypes,'WinDLL',return_value=types.SimpleNamespace(GetSystemDirectoryW=Api()),create=True),patch.object(fsprobe.subprocess,'run') as dispatch:
            with self.assertRaises(RuntimeError):fsprobe._junction('synthetic-link','synthetic-target')
            dispatch.assert_not_called()
    def test_21_expansion_sensitive_paths_prevent_dispatch(self):
        with patch.object(fsprobe,'_system_cmd') as lookup,patch.object(fsprobe.subprocess,'run') as dispatch:
            with self.assertRaises(RuntimeError):fsprobe._junction('synthetic%NAME%','synthetic-target')
            lookup.assert_not_called();dispatch.assert_not_called()
    def test_22_junction_dispatch_pins_image_and_quotes_paths(self):
        with patch.object(fsprobe,'_system_cmd',return_value='synthetic-system-cmd.exe'),patch.object(fsprobe.os.path,'isdir',return_value=True),patch.object(fsprobe.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)) as dispatch:
            fsprobe._junction('synthetic&link','synthetic-target')
            args,kwargs=dispatch.call_args
            self.assertEqual(kwargs['executable'],'synthetic-system-cmd.exe')
            self.assertIn('"synthetic&link"',args[0]);self.assertIn('/d /v:off /s /c',args[0])
    @unittest.skipUnless(os.name=='nt','Windows command-search regression')
    def test_18_hostile_current_directory_cannot_select_cmd(self):
        with tempfile.TemporaryDirectory(prefix='ast_command_search_synthetic_') as td:
            base=pathlib.Path(td);target=base/'target';target.mkdir()
            (base/'cmd.exe').write_bytes(b'SYNTHETIC INVALID EXECUTABLE - NO CODE')
            cwd=os.getcwd()
            try:
                os.chdir(base)
                cmd=fsprobe._system_cmd();self.assertTrue(os.path.isabs(cmd));self.assertNotEqual(os.path.dirname(cmd),str(base))
                fsprobe._junction(base/'link',target);self.assertTrue((base/'link').is_dir());os.rmdir(base/'link')
            finally:os.chdir(cwd)
    @unittest.skipUnless(os.name=='nt','Windows junction pathname regression')
    def test_19_junction_names_with_shell_metacharacters(self):
        with tempfile.TemporaryDirectory(prefix='ast_junction_paths_') as td:
            base=pathlib.Path(td);cwd=os.getcwd()
            try:
                os.chdir(base)
                for name in ['a&b','folder with spaces']:
                    parent=base/name;parent.mkdir();target=parent/'target';target.mkdir();link=parent/'link'
                    try:fsprobe._junction(link,target);self.assertTrue(link.is_dir())
                    finally:
                        if link.exists():os.rmdir(link)
            finally:os.chdir(cwd)
