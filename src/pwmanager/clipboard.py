"""Copy a password to the system clipboard and clear it again (I4).

Windows uses the Win32 API through ctypes. macOS uses pbcopy/pbpaste and
Linux uses wl-copy, xclip or xsel. The password is always passed through
stdin or memory, never as a command-line argument, so it does not show up
in the process list (same reason as M3).
"""

import os
import shutil
import subprocess
import sys
import time


class ClipboardError(Exception):
    pass


# ---------------------------------------------------------------- Windows

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _user32.OpenClipboard.argtypes = [wintypes.HWND]
    _user32.OpenClipboard.restype = wintypes.BOOL
    _user32.CloseClipboard.argtypes = []
    _user32.CloseClipboard.restype = wintypes.BOOL
    _user32.EmptyClipboard.argtypes = []
    _user32.EmptyClipboard.restype = wintypes.BOOL
    _user32.GetClipboardData.argtypes = [wintypes.UINT]
    _user32.GetClipboardData.restype = wintypes.HANDLE
    _user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _user32.SetClipboardData.restype = wintypes.HANDLE
    _user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    _user32.RegisterClipboardFormatW.restype = wintypes.UINT
    _kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    _kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalLock.restype = wintypes.LPVOID
    _kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalUnlock.restype = wintypes.BOOL
    _kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    _kernel32.GlobalFree.restype = wintypes.HGLOBAL

    _CF_UNICODETEXT = 13
    _GMEM_MOVEABLE = 0x0002

    def _open():
        # Another program can hold the clipboard for a moment, so retry.
        for _ in range(20):
            if _user32.OpenClipboard(None):
                return
            time.sleep(0.05)
        raise ClipboardError("could not open the clipboard")

    def _set_data(fmt, data):
        handle = _kernel32.GlobalAlloc(_GMEM_MOVEABLE, len(data))
        if not handle:
            raise ClipboardError("could not copy to the clipboard")
        ptr = _kernel32.GlobalLock(handle)
        ctypes.memmove(ptr, data, len(data))
        _kernel32.GlobalUnlock(handle)
        if not _user32.SetClipboardData(fmt, handle):
            _kernel32.GlobalFree(handle)
            raise ClipboardError("could not copy to the clipboard")

    def _copy(text):
        _open()
        try:
            _user32.EmptyClipboard()
            _set_data(_CF_UNICODETEXT, (text + "\0").encode("utf-16-le"))
            # Ask Windows to keep the password out of clipboard history
            # (Win+V) and out of the cloud clipboard.
            zero = (0).to_bytes(4, "little")
            for name in ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"):
                fmt = _user32.RegisterClipboardFormatW(name)
                if fmt:
                    _set_data(fmt, zero)
            fmt = _user32.RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing")
            if fmt:
                _set_data(fmt, zero)
        finally:
            _user32.CloseClipboard()

    def _paste():
        _open()
        try:
            handle = _user32.GetClipboardData(_CF_UNICODETEXT)
            if not handle:
                return ""
            ptr = _kernel32.GlobalLock(handle)
            if not ptr:
                return ""
            try:
                return ctypes.wstring_at(ptr)
            finally:
                _kernel32.GlobalUnlock(handle)
        finally:
            _user32.CloseClipboard()

    def _clear():
        _open()
        try:
            _user32.EmptyClipboard()
        finally:
            _user32.CloseClipboard()


# ---------------------------------------------------------------- macOS / Linux

else:

    def _tools():
        if sys.platform == "darwin":
            return ["pbcopy"], ["pbpaste"], None
        if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-copy"):
            return ["wl-copy"], ["wl-paste", "--no-newline"], ["wl-copy", "--clear"]
        if shutil.which("xclip"):
            return (["xclip", "-selection", "clipboard", "-in"],
                    ["xclip", "-selection", "clipboard", "-out"], None)
        if shutil.which("xsel"):
            return (["xsel", "--clipboard", "--input"],
                    ["xsel", "--clipboard", "--output"], ["xsel", "--clipboard", "--clear"])
        raise ClipboardError("no clipboard tool found (install wl-clipboard, xclip or xsel)")

    def _run(cmd, text=""):
        try:
            subprocess.run(cmd, input=text.encode("utf-8"), check=True, timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            raise ClipboardError("could not use the clipboard") from None

    def _copy(text):
        copy_cmd, _, _ = _tools()
        _run(copy_cmd, text)

    def _paste():
        _, paste_cmd, _ = _tools()
        try:
            out = subprocess.run(paste_cmd, capture_output=True, check=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return ""
        return out.stdout.decode("utf-8", "replace")

    def _clear():
        copy_cmd, _, clear_cmd = _tools()
        if clear_cmd:
            _run(clear_cmd)
        else:
            _run(copy_cmd, "")


# ---------------------------------------------------------------- shared

def copy(text):
    _copy(text)


def clear_if_unchanged(text):
    """Clear the clipboard, but only if it still holds our password.

    If the user copied something else in the meantime, it is left alone.
    """
    try:
        current = _paste()
    except ClipboardError:
        return False
    if current == text:
        _clear()
        return True
    return False
