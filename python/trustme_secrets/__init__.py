"""Read secrets from TrustMe.

    import trustme_secrets
    key = trustme_secrets.get("STRIPE_API_KEY")

The private key never leaves this process and is never sent anywhere. Each
request is authenticated with a freshly signed, single-use assertion that
expires in sixty seconds.

The key file is found from ``-X trustme_keyfile=...``, or by looking for a single
.TM file in the working directory, or by asking on a terminal.

The password is taken, in order, from ``-X trustme_password=...``,
``-X trustme_password_file=...``, a terminal prompt, or standard input. In a
pipeline prefer stdin or a password file: a value passed inline on the command
line is visible to anyone who can list processes on the machine.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
from base64 import urlsafe_b64encode
from pathlib import Path
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import _keycache
from ._tmfile import TmFile, TrustMeError, load

__all__ = ["get", "using", "use_key_file", "forget", "TrustMe", "TrustMeError"]

_SECRET_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_ASSERTION_LIFETIME = 60
_cache: dict = {}


def _b64url(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class TrustMe:
    """An unlocked key file, ready to fetch secrets."""

    def __init__(self, file: TmFile, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._file = file
        self._key = private_key

    @property
    def app_id(self) -> str:
        return self._file.app_id

    def fetch(self, secret_name: str) -> str:
        """Fetches one secret by name."""
        if not _SECRET_NAME.match(secret_name or ""):
            raise TrustMeError(f"Invalid secret name: {secret_name}")

        request = urllib.request.Request(
            self._file.api_url.rstrip("/") + "/secret",
            data=json.dumps({"secretName": secret_name}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self._assertion(),
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            try:
                reason = json.loads(detail).get("error", detail)
            except json.JSONDecodeError:
                reason = detail
            raise TrustMeError(self._describe(str(reason), secret_name)) from None
        except urllib.error.URLError as exc:
            raise TrustMeError(f"Could not reach TrustMe: {exc.reason}") from exc

        if "value" not in payload:
            raise TrustMeError("Malformed response from TrustMe.")
        return payload["value"]

    def _describe(self, code: str, secret_name: str) -> str:
        """Turns a server error code into something a person can act on.

        The secret name is always included: a bare "not found" is useless when
        a config file references a dozen of them.
        """
        app = self._file.app_id
        if code == "secret_not_found":
            return (f'Secret "{secret_name}" does not exist in application "{app}". '
                    "Add it in the TrustMe console.")
        if code == "key_revoked":
            return (f'The key file for application "{app}" has been revoked (while fetching '
                    f'"{secret_name}"). Generate a new one in the TrustMe console.')
        if code == "unknown_key":
            return (f'The key file for application "{app}" is not registered with TrustMe (while '
                    f'fetching "{secret_name}"). Generate a new one in the TrustMe console.')
        if code == "bad_signature":
            return (f'TrustMe rejected the request for "{secret_name}": the signature did not verify. '
                    f'The key file may not match what the console holds for "{app}".')
        if code in ("replay_detected", "bad_lifetime"):
            return (f'TrustMe rejected the request for "{secret_name}" ({code}). '
                    "Check that this machine's clock is correct.")
        if code == "decrypt_failed":
            return (f'TrustMe could not decrypt "{secret_name}" on the server. This is a server-side '
                    "problem, not something in your application.")
        return f'TrustMe refused the request for "{secret_name}" in application "{app}": {code}'

    def _assertion(self) -> str:
        now = int(time.time())
        header = {"alg": "ES256", "typ": "JWT", "kid": self._file.key_id}
        claims = {
            "iss": self._file.app_id,
            "aud": "trustme",
            "iat": now,
            "exp": now + _ASSERTION_LIFETIME,
            "jti": secrets.token_hex(16),
        }
        signing_input = ".".join(
            _b64url(json.dumps(part, separators=(",", ":")).encode("utf-8"))
            for part in (header, claims)
        ).encode("ascii")

        # cryptography returns a DER sequence; JOSE wants the raw r||s pair.
        der = self._key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return signing_input.decode("ascii") + "." + _b64url(raw)


def _option(name: str, *aliases: str) -> Optional[str]:
    """Reads a ``-X name=value`` interpreter option, or a ``--name=value`` argument.

    ``-X`` is preferred because it never collides with the application's own
    argument parsing.
    """
    for key in (name, *aliases):
        value = sys._xoptions.get(key)
        if isinstance(value, str) and value:
            return value
    for key in (name, *aliases):
        flag = "--" + key.replace("_", "-") + "="
        for arg in sys.argv[1:]:
            if arg.startswith(flag):
                return arg[len(flag):]
    return None


def _key_files_here() -> list[Path]:
    try:
        return sorted(p for p in Path(".").iterdir() if p.suffix.lower() == ".tm" and p.is_file())
    except OSError:
        return []


def _resolve_key_file() -> Path:
    configured = _option("trustme_keyfile", "trustme_key_file")
    if configured:
        path = Path(configured.strip())
        if not path.is_file():
            raise TrustMeError(f"-X trustme_keyfile points at a missing file: {configured}")
        return path

    found = _key_files_here()
    if len(found) == 1:
        return found[0]

    if sys.stdin.isatty():
        prompt = (
            "Path to your .TM key file: "
            if not found
            else "Several .TM files are here. Path to the one to use: "
        )
        typed = input(prompt).strip()
        if typed:
            path = Path(typed)
            if not path.is_file():
                raise TrustMeError(f"No such file: {typed}")
            return path

    raise TrustMeError(
        "No .TM key file found. Pass -X trustme_keyfile=<path>, or run where one is present."
        if not found
        else "Several .TM files found. Pass -X trustme_keyfile=<path> to choose one."
    )


def _resolve_password() -> str:
    inline = _option("trustme_password")
    if inline:
        return inline

    password_file = _option("trustme_password_file")
    if password_file:
        try:
            return Path(password_file.strip()).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise TrustMeError(f"Could not read -X trustme_password_file: {exc}") from exc

    if sys.stdin.isatty():
        typed = getpass.getpass("TrustMe key file password: ")
        if typed:
            return typed
        raise TrustMeError("No password entered.")

    # No terminal, so this is a pipeline: take the password from stdin, which
    # unlike a command-line flag does not show up in the process list.
    # No tty: a pipeline, or an IDE that redirected the streams. Stdin is the
    # only route left, and the prompt has to be printed explicitly - without it
    # an IDE run just hangs with no hint that anything is waiting for input.
    print("TrustMe key file password: ", end="", file=sys.stderr, flush=True)
    line = sys.stdin.readline().rstrip(chr(13) + chr(10))
    print(file=sys.stderr)
    if line:
        return line

    raise TrustMeError(
        "No password available. Pipe it on stdin, or pass "
        "-X trustme_password_file=<path>, or -X trustme_password=<value>."
    )


def _from_pkcs8(file: TmFile, pkcs8: bytes) -> TrustMe:
    private_key = serialization.load_der_private_key(pkcs8, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TrustMeError("Key file does not contain a usable P-256 key.")
    return TrustMe(file, private_key)


def _decrypt(file: TmFile, path: Path, password: str) -> bytes:
    derived = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=file.salt,
        time_cost=file.time_cost,
        memory_cost=file.memory_cost_kib,
        parallelism=file.parallelism,
        hash_len=32,
        type=Type.ID,
    )
    try:
        # The GCM tag doubles as the password check: a wrong password fails here
        # rather than producing plausible-looking rubbish.
        return AESGCM(derived).decrypt(file.nonce, file.ciphertext + file.tag, None)
    except Exception:
        raise TrustMeError(f"Incorrect password for {Path(path).name}.") from None


def _unlock(path: Path, password: str) -> TrustMe:
    file = load(path)
    pkcs8 = _decrypt(file, path, password)
    _keycache.store(file.key_id, pkcs8)      # remember for next run
    return _from_pkcs8(file, pkcs8)


def using(key_file: Optional[str | Path] = None, password: Optional[str] = None) -> TrustMe:
    """Opens a key file.

    Without a password, a key this machine already remembers is used directly;
    otherwise the password is asked for, read from stdin, or taken from the
    command line. With an explicit password the file is always unlocked with it,
    so a wrong one fails rather than reusing an earlier success.
    """
    path = Path(key_file) if key_file else _resolve_key_file()

    if password is None:
        slot = str(path.resolve())
        if slot not in _cache:
            # The header is plaintext, so the key id is readable without
            # unlocking anything - that is what makes a cache lookup possible
            # before prompting.
            file = load(path)
            remembered = _keycache.load(file.key_id)
            _cache[slot] = (_from_pkcs8(file, remembered) if remembered is not None
                            else _unlock(path, _resolve_password()))
        return _cache[slot]

    cache_key = (str(path.resolve()), hashlib.sha256(password.encode("utf-8")).hexdigest())
    if cache_key not in _cache:
        _cache[cache_key] = _unlock(path, password)
    return _cache[cache_key]


def forget(key_file: str | Path) -> bool:
    """Forgets a key this machine has remembered, so the next run asks again."""
    path = Path(key_file)
    file = load(path)
    _cache.pop(str(path.resolve()), None)
    return _keycache.forget(file.key_id)


# Resolved once per process. Standard input in particular can only be read once,
# so a second get() must not go looking for the password again.
_defaults: dict[str, object] = {}


def use_key_file(key_file: str | Path) -> None:
    """Points :func:`get` at a specific key file.

    Use this instead of relying on ``-X trustme_keyfile`` or on finding a single
    .TM file in the working directory. The password is still asked for, or read
    from stdin, on first use.
    """
    path = Path(key_file)
    if not path.is_file():
        raise TrustMeError(f"No such key file: {key_file}")
    _defaults["key_file"] = path


def get(secret_name: str) -> str:
    """Fetches a secret using the default key file and password."""
    if "key_file" not in _defaults:
        _defaults["key_file"] = _resolve_key_file()
    return using(_defaults["key_file"]).fetch(secret_name)
