"""Pinned trusted root: one directory handle; every lookup is relative to it.

Historical procedure-based rc4 implementation from SPEC.md (provenance unresolved) (R1-R5, W1, W6, W7).
"""
import ctypes
import re
import threading
from ctypes import wintypes as wt

from ..errors import AccessDenied
from . import _win32 as w

HANDLE_STATS = {"opened": 0, "closed": 0}
_stats_lock = threading.Lock()
_DRIVE_ABS = re.compile(r"[A-Za-z]:\\")


def _count(key):
    with _stats_lock:
        HANDLE_STATS[key] += 1


def release(handle):
    """Close a handle this package opened and count it."""
    if handle:
        if not w.api().close(handle):
            raise AccessDenied("Native handle cleanup failed")
        _count("closed")


def query(handle):
    """Return BY_HANDLE_FILE_INFORMATION for a handle or deny."""
    info = w.ByHandleInfo()
    if not w.api().info(handle, ctypes.byref(info)):
        raise AccessDenied("Handle information unavailable")
    return info


def identity_of(info):
    return (info.dwVolumeSerialNumber, (info.nFileIndexHigh << 32) | info.nFileIndexLow)


def final_path(handle):
    """Normalised final DOS path of an open handle (lower-case, no trailing separator)."""
    a = w.api()
    size = 512
    while True:
        buf = ctypes.create_unicode_buffer(size)
        n = a.final_path(handle, buf, size, 0)
        if n == 0:
            raise AccessDenied("Final path unavailable")
        if n < size:
            return buf.value.rstrip("\\").lower()
        size = n + 1


class TrustedRoot:
    """Holds the root directory open for the lifetime of the pin."""

    def __init__(self, path):
        a = w.api()
        if not isinstance(path, str) or not _DRIVE_ABS.match(path) or "\x00" in path:
            raise AccessDenied("Root must be an absolute local drive path")
        self._guard = threading.RLock()
        self._handle = None
        h = a.open_win32(path, w.FILE_LIST_DIRECTORY | w.FILE_TRAVERSE | w.FILE_READ_ATTRIBUTES | w.SYNCHRONIZE,
                         w.SHARE_READ | w.SHARE_WRITE, None, w.WIN32_OPEN_EXISTING,
                         w.WIN32_FLAG_BACKUP_SEMANTICS | w.WIN32_FLAG_OPEN_REPARSE_POINT, None)
        if h is None or h == a.bad_handle:
            raise AccessDenied("Root directory could not be opened")
        _count("opened")
        try:
            info = query(h)
            if not info.dwFileAttributes & w.ATTR_DIRECTORY or info.dwFileAttributes & w.ATTR_REPARSE_POINT:
                raise AccessDenied("Root is not a plain directory")
            self._identity = identity_of(info)
            self.final = final_path(h)
        except:  # noqa: E722 - release on any failure, then re-raise
            release(h)
            raise
        self._handle = h
        self.path = path

    @property
    def closed(self):
        return self._handle is None

    def validate(self):
        with self._guard:
            if self._handle is None:
                raise AccessDenied("Pin has been released")
            if identity_of(query(self._handle)) != self._identity:
                raise AccessDenied("Pinned directory identity mismatch")
            return self._handle

    def open_relative(self, parent, name, want_directory):
        """Open one component under `parent` with reparse traversal disabled. Caller releases the handle."""
        a = w.api()
        units = len(name.encode("utf-16-le")) // 2
        if not name or units > 255:
            raise AccessDenied("Component empty or too long")
        text = ctypes.create_unicode_buffer(name)
        ustr = w.UnicodeString(units * 2, units * 2 + 2, ctypes.cast(text, ctypes.c_void_p))
        attrs = w.ObjectAttributes(ctypes.sizeof(w.ObjectAttributes), parent, ctypes.pointer(ustr),
                                   w.OBJ_ATTR_DONT_REPARSE, None, None)
        iosb = w.IoStatusBlock()
        out = wt.HANDLE()
        if want_directory:
            access = w.FILE_TRAVERSE | w.FILE_READ_ATTRIBUTES | w.SYNCHRONIZE
            share = w.SHARE_READ | w.SHARE_WRITE | w.SHARE_DELETE
            kind = w.OPT_DIRECTORY_FILE
        else:
            access = w.FILE_READ_DATA | w.FILE_READ_ATTRIBUTES | w.SYNCHRONIZE
            share = w.SHARE_READ
            kind = w.OPT_NON_DIRECTORY_FILE
        try:
            status = a.nt_open(ctypes.byref(out), access, ctypes.byref(attrs), ctypes.byref(iosb), None, 0,
                               share, w.CREATE_DISPOSITION_OPEN,
                               kind | w.OPT_SYNCHRONOUS_IO_NONALERT | w.OPT_OPEN_REPARSE_POINT, None, 0)
            if status < 0 or not out.value:
                raise AccessDenied("Relative open denied (NTSTATUS 0x%08X)" % (status & 0xFFFFFFFF))
            h = out.value
            info = query(h)
            if info.dwFileAttributes & w.ATTR_REPARSE_POINT:
                raise AccessDenied("Reparse point denied")
            if bool(info.dwFileAttributes & w.ATTR_DIRECTORY) != bool(want_directory):
                raise AccessDenied("Unexpected object type")
            if not want_directory and info.nNumberOfLinks != 1:
                raise AccessDenied("Hard-linked file denied (link count %d)" % info.nNumberOfLinks)
        except:  # noqa: E722 - release on any failure, then re-raise
            if out.value:
                _count('opened')
                release(out.value)
            raise
        _count('opened')
        return h, info

    def close(self):
        with self._guard:
            h, self._handle = self._handle, None
        release(h)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
