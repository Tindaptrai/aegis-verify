"""Create private evidence directories (issue #110).

POSIX uses mkdir mode 0700. On Windows the mode is not enough: Python 3.13 turns
mode 0700 into a DACL that also grants SYSTEM and Administrators, and older versions
ignore it. Windows directories are therefore created with CreateDirectoryW and a
protected DACL that grants only the current user, in one call, so there is no window
with a broader ACL and nothing to clean up if it fails. The owner is the token's
default owner: Administrators in an elevated session, which owner checks reject.
"""

import ctypes
import os
from pathlib import Path
import re


def mkdir_private(path, *, exist_ok=False):
    """Create one directory; never repair or broaden an existing directory."""
    target = Path(path)
    try:
        _create(target)
    except FileExistsError:
        if exist_ok and target.is_dir():
            return target
        raise
    return target


def _create(target):
    if os.name == 'nt':
        _create_windows(target)
    else:
        target.mkdir(mode=0o700)


if os.name == 'nt':
    from ctypes import wintypes

    _advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    _kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _SDDL_REVISION_1 = 1
    _SID = re.compile(r'S-1-[0-9]+(?:-[0-9]+){1,14}')

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [('nLength', wintypes.DWORD), ('lpSecurityDescriptor', ctypes.c_void_p),
                    ('bInheritHandle', wintypes.BOOL)]

    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
    _kernel32.CreateDirectoryW.restype = wintypes.BOOL
    _advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL
    _advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                              wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _advapi32.GetTokenInformation.restype = wintypes.BOOL
    _advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    _advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG)]
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL

    def _fail():
        raise ctypes.WinError(ctypes.get_last_error())

    def _current_user_sid():
        token = wintypes.HANDLE()
        if not _advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
            _fail()
        try:
            size = wintypes.DWORD()
            _advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            if not _advapi32.GetTokenInformation(token, _TOKEN_USER, buffer, size, ctypes.byref(size)):
                _fail()
            # TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first field is the SID pointer.
            sid = ctypes.c_void_p.from_buffer(buffer).value
            text = ctypes.c_void_p()
            if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                _fail()
            try:
                value = ctypes.wstring_at(text.value)
            finally:
                _kernel32.LocalFree(text)
        finally:
            _kernel32.CloseHandle(token)
        if not _SID.fullmatch(value):
            raise OSError('unexpected_user_sid')
        return value

    def _create_windows(target):
        # Protected DACL, one allow ACE: full control for the user, inherited by files
        # and subdirectories. This is exactly what the Operations owner-only check accepts.
        sddl = f'D:P(A;OICI;FA;;;{_current_user_sid()})'
        descriptor = ctypes.c_void_p()
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), None):
            _fail()
        try:
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
            if not _kernel32.CreateDirectoryW(str(target), ctypes.byref(attributes)):
                _fail()
        finally:
            _kernel32.LocalFree(descriptor)
