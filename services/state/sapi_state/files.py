"""Private, durable files kept outside the database backup boundary."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from functools import lru_cache


@lru_cache(maxsize=1)
def _user_sid():
    result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True)
    import csv
    return next(csv.reader(result.stdout.splitlines()))[1]


def protect(path):
    path = Path(path)
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        api = ctypes.WinDLL("advapi32", use_last_error=True); kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD))
        api.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        api.SetFileSecurityW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p); api.SetFileSecurityW.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = (ctypes.c_void_p,); kernel.LocalFree.restype = ctypes.c_void_p
        descriptor = ctypes.c_void_p()
        inheritance = "OICI" if path.is_dir() else ""
        sddl = "D:P(A;" + inheritance + ";FA;;;" + _user_sid() + ")(A;" + inheritance + ";FA;;;SY)"
        if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None): raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not api.SetFileSecurityW(str(path), 0x80000004, descriptor): raise ctypes.WinError(ctypes.get_last_error())
        finally: kernel.LocalFree(descriptor)
    else:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def private_directory(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    protect(path)
    return path


def write_private(path, value, *, replace=False):
    """Flush bytes before atomic replacement; caller holds the database write lock."""
    path = Path(path)
    if path.exists() and not replace:
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".sapi-", dir=path.parent)
    try:
        protect(temporary)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            # link is exclusive, unlike replace; initialization never overwrites secrets.
            os.link(temporary, path)
            os.unlink(temporary)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
    finally:
        if descriptor is not None: os.close(descriptor)
        if os.path.exists(temporary): os.unlink(temporary)


def write_json(path, value, *, replace=False):
    write_private(path, (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode(), replace=replace)
