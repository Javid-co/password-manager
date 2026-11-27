"""Per-user access control (V5, A1-A4 in docs/design.md).

A vault belongs to the operating system user who created it. Every file the
program uses (the vault, its folder, the lock file and the log) must be owned
by the user running pwm, and only that user may have access to it:

- Linux/macOS: the owner uid must be our effective uid, and the group/other
  permission bits must be 0 (files 0600, folders 0700).
- Windows: the owner SID must be our user SID, and the file's ACL may only
  give access to our user. New files get a protected ACL with one entry:
  full control for the current user. Inherited entries (SYSTEM,
  Administrators, Users ...) are removed.

A file owned by someone else is refused with AccessDenied. A file that we
own but that has too open permissions is fixed, and the caller logs it.
That is safe because if someone else could already read it, refusing to
open it now would not undo that. Fixing it stops it from happening again.
"""

import os
import stat

from .errors import PwmError

IS_WINDOWS = os.name == "nt"


class AccessDenied(PwmError):
    pass


# ---------------------------------------------------------------- Windows

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _ACL_REVISION = 2
    _FILE_ALL_ACCESS = 0x001F01FF
    _OBJECT_INHERIT_ACE = 0x1
    _CONTAINER_INHERIT_ACE = 0x2
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _ACCESS_DENIED_ACE_TYPE = 1

    class _ACL(ctypes.Structure):
        _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte),
                    ("AclSize", wintypes.WORD), ("AceCount", wintypes.WORD),
                    ("Sbz2", wintypes.WORD)]

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte),
                    ("AceSize", wintypes.WORD)]

    class _ACCESS_ALLOWED_ACE(ctypes.Structure):
        _fields_ = [("Header", _ACE_HEADER), ("Mask", wintypes.DWORD),
                    ("SidStart", wintypes.DWORD)]

    _P = ctypes.c_void_p
    _PP = ctypes.POINTER(ctypes.c_void_p)

    def _fn(dll, name, argtypes, restype):
        f = getattr(dll, name)
        f.argtypes = argtypes
        f.restype = restype
        return f

    _OpenProcessToken = _fn(_advapi32, "OpenProcessToken",
                            [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)],
                            wintypes.BOOL)
    _GetTokenInformation = _fn(_advapi32, "GetTokenInformation",
                               [wintypes.HANDLE, ctypes.c_int, _P, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL)
    _GetLengthSid = _fn(_advapi32, "GetLengthSid", [_P], wintypes.DWORD)
    _EqualSid = _fn(_advapi32, "EqualSid", [_P, _P], wintypes.BOOL)
    _ConvertSidToStringSidW = _fn(_advapi32, "ConvertSidToStringSidW",
                                  [_P, ctypes.POINTER(_P)], wintypes.BOOL)
    _GetNamedSecurityInfoW = _fn(_advapi32, "GetNamedSecurityInfoW",
                                 [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                  _PP, _PP, _PP, _PP, _PP], wintypes.DWORD)
    _SetNamedSecurityInfoW = _fn(_advapi32, "SetNamedSecurityInfoW",
                                 [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
                                  _P, _P, _P, _P], wintypes.DWORD)
    _InitializeAcl = _fn(_advapi32, "InitializeAcl",
                         [_P, wintypes.DWORD, wintypes.DWORD], wintypes.BOOL)
    _AddAccessAllowedAceEx = _fn(_advapi32, "AddAccessAllowedAceEx",
                                 [_P, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, _P],
                                 wintypes.BOOL)
    _GetAce = _fn(_advapi32, "GetAce", [_P, wintypes.DWORD, _PP], wintypes.BOOL)
    _GetCurrentProcess = _fn(_kernel32, "GetCurrentProcess", [], wintypes.HANDLE)
    _CloseHandle = _fn(_kernel32, "CloseHandle", [wintypes.HANDLE], wintypes.BOOL)
    _LocalFree = _fn(_kernel32, "LocalFree", [_P], _P)

    _user_sid_cache = None

    def _user_sid():
        """The SID of the user running this process, as a ctypes buffer."""
        global _user_sid_cache
        if _user_sid_cache is not None:
            return _user_sid_cache
        token = wintypes.HANDLE()
        if not _OpenProcessToken(_GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
            raise AccessDenied("could not check the current user")
        try:
            size = wintypes.DWORD()
            _GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
            info = ctypes.create_string_buffer(size.value)
            if not _GetTokenInformation(token, _TOKEN_USER, info, size, ctypes.byref(size)):
                raise AccessDenied("could not check the current user")
        finally:
            _CloseHandle(token)
        # TOKEN_USER starts with a pointer to the SID.
        psid = ctypes.c_void_p.from_buffer(info).value
        length = _GetLengthSid(psid)
        sid = ctypes.create_string_buffer(length)
        ctypes.memmove(sid, psid, length)
        _user_sid_cache = sid
        return sid

    def _sid_to_str(psid):
        out = ctypes.c_void_p()
        if not _ConvertSidToStringSidW(psid, ctypes.byref(out)):
            return "unknown"
        try:
            return ctypes.wstring_at(out.value)
        finally:
            _LocalFree(out)

    def current_user():
        return _sid_to_str(ctypes.addressof(_user_sid()))

    def _read_security(path):
        """Return (owned_by_us, others_have_access)."""
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        sd = ctypes.c_void_p()
        rc = _GetNamedSecurityInfoW(
            path, _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(sd))
        if rc != 0:
            raise AccessDenied("could not check the permissions of " + path)
        try:
            me = ctypes.addressof(_user_sid())
            owned = bool(owner.value) and bool(_EqualSid(owner.value, me))
            if not dacl.value:
                return owned, True  # a NULL DACL means everyone has full access
            acl = _ACL.from_address(dacl.value)
            for i in range(acl.AceCount):
                ace = ctypes.c_void_p()
                if not _GetAce(dacl.value, i, ctypes.byref(ace)):
                    return owned, True
                header = _ACE_HEADER.from_address(ace.value)
                if header.AceType == _ACCESS_DENIED_ACE_TYPE:
                    continue
                if header.AceType != _ACCESS_ALLOWED_ACE_TYPE:
                    return owned, True  # some other kind of allow entry, be careful
                sid = ace.value + _ACCESS_ALLOWED_ACE.SidStart.offset
                if not _EqualSid(sid, me):
                    return owned, True
            return owned, False
        finally:
            _LocalFree(sd.value)

    def _set_private(path, is_dir):
        """Replace the ACL with one entry: full control for the current user."""
        me = _user_sid()
        size = (ctypes.sizeof(_ACL) + ctypes.sizeof(_ACCESS_ALLOWED_ACE)
                - ctypes.sizeof(wintypes.DWORD) + _GetLengthSid(ctypes.addressof(me)))
        size = (size + 3) & ~3
        acl = ctypes.create_string_buffer(size)
        flags = (_OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE) if is_dir else 0
        if (not _InitializeAcl(acl, size, _ACL_REVISION)
                or not _AddAccessAllowedAceEx(acl, _ACL_REVISION, flags, _FILE_ALL_ACCESS,
                                              ctypes.addressof(me))):
            raise AccessDenied("could not set the permissions of " + path)
        rc = _SetNamedSecurityInfoW(
            path, _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None)
        if rc != 0:
            raise AccessDenied("could not set the permissions of " + path)

    def _check(path, fd, is_dir):
        owned, others = _read_security(path)
        if not owned:
            raise AccessDenied(path + " belongs to another user")
        if others:
            _set_private(path, is_dir)
            return True
        return False

    def _make_private(path, fd, is_dir):
        _set_private(path, is_dir)


# ---------------------------------------------------------------- Linux / macOS

else:

    def current_user():
        return str(os.geteuid())

    def _check(path, fd, is_dir):
        st = os.fstat(fd) if fd is not None else os.lstat(path)
        if st.st_uid != os.geteuid():
            raise AccessDenied(path + " belongs to another user")
        if stat.S_IMODE(st.st_mode) & 0o077:
            _make_private(path, fd, is_dir)
            return True
        return False

    def _make_private(path, fd, is_dir):
        mode = 0o700 if is_dir else 0o600
        if fd is not None:
            os.fchmod(fd, mode)
        else:
            os.chmod(path, mode)


# ---------------------------------------------------------------- shared

def check_file(path, fd=None):
    """Refuse a file owned by another user, fix too open permissions.

    Returns True if the permissions had to be fixed. On Linux the check uses
    the open file descriptor when there is one, so it checks the file that
    was really opened and not whatever the path points to now.
    """
    return _check(path, fd, False)


def check_dir(path):
    return _check(path, None, True)


def make_private_file(path, fd=None):
    _make_private(path, fd, False)


def make_private_dir(path):
    _make_private(path, None, True)


def open_private(path, flags):
    """Open a file that only the current user can use, creating it if needed.

    Returns (fd, fixed). A new file is created with O_EXCL and made private
    before anything is written to it. An existing file goes through
    check_file. Symlinks are refused (V7).
    """
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        if stat.S_ISLNK(os.lstat(path).st_mode):
            raise AccessDenied("refusing to use a symlink: " + path)
    except FileNotFoundError:
        pass
    try:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        try:
            make_private_file(path, fd)
        except BaseException:
            os.close(fd)
            raise
        return fd, False
    fd = os.open(path, flags)
    try:
        return fd, check_file(path, fd)
    except BaseException:
        os.close(fd)
        raise
