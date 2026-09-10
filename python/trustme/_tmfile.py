"""Reader for the .TM container (format version 2).

The layout is public by design. The only secret is the password that unlocks the
private key held inside it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"TMKF"
VERSION = 2


class TrustMeError(Exception):
    """Raised when a key file cannot be read or a secret cannot be fetched."""


@dataclass(frozen=True)
class TmFile:
    app_id: str
    key_id: str
    api_url: str
    public_key: bytes
    salt: bytes
    memory_cost_kib: int
    time_cost: int
    parallelism: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes


class _Cursor:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def take(self, count: int) -> bytes:
        if self._pos + count > len(self._data):
            raise TrustMeError("Key file ended unexpectedly.")
        chunk = self._data[self._pos : self._pos + count]
        self._pos += count
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def str8(self) -> str:
        return self.take(self.u8()).decode("utf-8")

    def str16(self) -> str:
        return self.take(self.u16()).decode("utf-8")

    def blob16(self) -> bytes:
        return self.take(self.u16())


def load(path: Path) -> TmFile:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise TrustMeError(f"Could not read key file {path}: {exc}") from exc

    if len(raw) < 100:
        raise TrustMeError(f"File is too small to be a key file: {path}")

    body, stated = raw[:-32], raw[-32:]
    if not hashlib.sha256(body).digest() == stated:
        raise TrustMeError("Key file is corrupt: checksum does not match.")

    cursor = _Cursor(raw)
    if cursor.take(4) != MAGIC:
        raise TrustMeError(f"Not a TrustMe key file: {path}")

    version = cursor.u8()
    if version != VERSION:
        raise TrustMeError(
            f"Unsupported key file version {version}. "
            "Regenerate this file from the TrustMe console."
        )
    cursor.u8()  # flags

    return TmFile(
        app_id=cursor.str8(),
        key_id=cursor.str8(),
        api_url=cursor.str16(),
        public_key=cursor.blob16(),
        salt=cursor.take(16),
        memory_cost_kib=cursor.u32(),
        time_cost=cursor.u32(),
        parallelism=cursor.u8(),
        nonce=cursor.take(12),
        ciphertext=cursor.blob16(),
        tag=cursor.take(16),
    )
