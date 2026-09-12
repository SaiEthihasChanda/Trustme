"""Remembers an unlocked private key for this Windows account.

The key is sealed with DPAPI under CurrentUser scope, so another account on the
same machine cannot read it and copying the file elsewhere yields nothing. Any
process running as you can use it, which is the same bargain ssh-agent makes.

On anything other than Windows the cache is disabled and every run asks.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Optional

_WINDOWS = sys.platform == "win32"
_CRYPTPROTECT_UI_FORBIDDEN = 0x01


def _option(name: str) -> Optional[str]:
    value = sys._xoptions.get(name)
    if isinstance(value, str) and value:
        return value
    flag = "--" + name.replace("_", "-") + "="
    for arg in sys.argv[1:]:
        if arg.startswith(flag):
            return arg[len(flag):]
    return None


def enabled() -> bool:
    if not _WINDOWS:
        return False
    return (_option("trustme_cache") or "true").lower() != "false"


_DEBUG = _option("trustme_debug") is not None


def _debug(message: str) -> None:
    if _DEBUG:
        print("TrustMe: " + message, file=sys.stderr)


def _directory() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "TrustMe" / "keys"


def _file_for(key_id: str) -> Path:
    return _directory() / (key_id + ".bin")


if _WINDOWS:
    from ctypes import wintypes

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for _fn in (_crypt32.CryptProtectData, _crypt32.CryptUnprotectData):
        _fn.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]

    def _dpapi(fn, data: bytes) -> bytes:
        buf = ctypes.create_string_buffer(data, len(data))  # kept alive across the call
        inp = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        out = _DATA_BLOB()
        ok = fn(ctypes.byref(inp), None, None, None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out))
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)

    def _protect(data: bytes) -> bytes:
        return _dpapi(_crypt32.CryptProtectData, data)

    def _unprotect(data: bytes) -> bytes:
        return _dpapi(_crypt32.CryptUnprotectData, data)


def load(key_id: str) -> Optional[bytes]:
    """Returns the remembered private key for this key id, or None."""
    if not enabled():
        _debug("cache disabled (" + ("-X trustme_cache=false" if _WINDOWS else "not Windows") + ")")
        return None
    path = _file_for(key_id)
    if not path.is_file():
        _debug(f"no cached key at {path}")
        return None
    try:
        key = _unprotect(path.read_bytes())
        _debug(f"using cached key from {path}")
        return key
    except Exception as exc:  # another account, corrupt, or DPAPI refused it
        print(f"TrustMe: cached key at {path} could not be read ({type(exc).__name__}: {exc}); "
              "asking for the password.", file=sys.stderr)
        return None


def store(key_id: str, private_key: bytes) -> None:
    """Remembers an unlocked private key. Failure is reported, never fatal."""
    if not enabled():
        return
    path = _file_for(key_id)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_protect(private_key))
        _debug(f"remembered key at {path}")
    except Exception as exc:
        print(f"TrustMe: could not remember the key on this machine ({type(exc).__name__}: {exc}). "
              "You will be asked for the password on every run.", file=sys.stderr)


def forget(key_id: str) -> bool:
    """Forgets one remembered key. Returns True if something was removed."""
    path = _file_for(key_id)
    if not path.exists():
        return False
    path.unlink()
    return True
