"""Native Win32 / NT declarations used by the contained reader.

Written for rc4 from the public Microsoft documentation of each function and
structure (see CLEANROOM_LOG.md). Loaded lazily so that importing the package
on non-Windows platforms works; every native call then fails closed.
"""
import ctypes
import os
from ctypes import wintypes as wt

# --- access rights, sharing, dispositions, options (winnt.h / ntifs.h docs) ---
SYNCHRONIZE = 0x00100000
FILE_READ_DATA = 0x0001            # same bit as FILE_LIST_DIRECTORY
FILE_LIST_DIRECTORY = 0x0001
FILE_TRAVERSE = 0x0020
FILE_READ_ATTRIBUTES = 0x0080

SHARE_READ, SHARE_WRITE, SHARE_DELETE = 0x1, 0x2, 0x4

CREATE_DISPOSITION_OPEN = 0x1                 # FILE_OPEN (NtCreateFile)
OPT_DIRECTORY_FILE = 0x00000001
OPT_SYNCHRONOUS_IO_NONALERT = 0x00000020
OPT_NON_DIRECTORY_FILE = 0x00000040
OPT_OPEN_REPARSE_POINT = 0x00200000

OBJ_ATTR_DONT_REPARSE = 0x00001000

WIN32_OPEN_EXISTING = 3
WIN32_FLAG_BACKUP_SEMANTICS = 0x02000000
WIN32_FLAG_OPEN_REPARSE_POINT = 0x00200000

ATTR_DIRECTORY = 0x00000010
ATTR_REPARSE_POINT = 0x00000400


class UnicodeString(ctypes.Structure):
    _fields_ = [("Length", wt.USHORT), ("MaximumLength", wt.USHORT), ("Buffer", ctypes.c_void_p)]


class ObjectAttributes(ctypes.Structure):
    _fields_ = [("Length", wt.ULONG), ("RootDirectory", wt.HANDLE),
                ("ObjectName", ctypes.POINTER(UnicodeString)), ("Attributes", wt.ULONG),
                ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p)]


class IoStatusBlock(ctypes.Structure):
    # union { NTSTATUS Status; PVOID Pointer; } is pointer-sized
    _fields_ = [("StatusOrPointer", ctypes.c_void_p), ("Information", ctypes.c_size_t)]


class FileTime(ctypes.Structure):
    _fields_ = [("Low", wt.DWORD), ("High", wt.DWORD)]


class ByHandleInfo(ctypes.Structure):
    _fields_ = [("dwFileAttributes", wt.DWORD), ("ftCreationTime", FileTime),
                ("ftLastAccessTime", FileTime), ("ftLastWriteTime", FileTime),
                ("dwVolumeSerialNumber", wt.DWORD), ("nFileSizeHigh", wt.DWORD),
                ("nFileSizeLow", wt.DWORD), ("nNumberOfLinks", wt.DWORD),
                ("nFileIndexHigh", wt.DWORD), ("nFileIndexLow", wt.DWORD)]


class _Api:
    """Bound native entry points; created on first use (Windows only)."""

    def __init__(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        ntapi = ctypes.WinDLL("ntdll")
        self.open_win32 = kernel.CreateFileW
        self.open_win32.restype = wt.HANDLE
        self.open_win32.argtypes = (wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                    wt.DWORD, wt.DWORD, wt.HANDLE)
        self.close = kernel.CloseHandle
        self.close.restype = wt.BOOL
        self.close.argtypes = (wt.HANDLE,)
        self.info = kernel.GetFileInformationByHandle
        self.info.restype = wt.BOOL
        self.info.argtypes = (wt.HANDLE, ctypes.POINTER(ByHandleInfo))
        self.read = kernel.ReadFile
        self.read.restype = wt.BOOL
        self.read.argtypes = (wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p)
        self.final_path = kernel.GetFinalPathNameByHandleW
        self.final_path.restype = wt.DWORD
        self.final_path.argtypes = (wt.HANDLE, wt.LPWSTR, wt.DWORD, wt.DWORD)
        self.nt_open = ntapi.NtCreateFile
        self.nt_open.restype = ctypes.c_long
        self.nt_open.argtypes = (ctypes.POINTER(wt.HANDLE), wt.DWORD, ctypes.POINTER(ObjectAttributes),
                                 ctypes.POINTER(IoStatusBlock), ctypes.c_void_p, wt.ULONG, wt.ULONG,
                                 wt.ULONG, wt.ULONG, ctypes.c_void_p, wt.ULONG)
        self.bad_handle = wt.HANDLE(-1).value


_api = None


def api():
    """Return the native API, or raise NotImplementedError off Windows (fail closed)."""
    global _api
    if not os.name == "nt":
        raise NotImplementedError("winfs: native Windows API unavailable on this platform (fail closed)")
    if _api is None:
        _api = _Api()
    return _api
