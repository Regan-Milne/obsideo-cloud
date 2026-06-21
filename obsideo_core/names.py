"""Deterministic filename encryption (Level 1 metadata privacy).

Object keys (folder paths + filenames) would otherwise reach Obsideo in the clear,
leaking the *shape* of your data even though contents are encrypted. This encrypts
each path component client-side with **AES-SIV** (deterministic, misuse-resistant
authenticated encryption) keyed off your data key, so `photos/tax.pdf` is stored
as opaque tokens.

Why deterministic: identical input → identical token, which is what lets the
server still do prefix listing — `ls` lists under the encrypted prefix and the
client decrypts the returned tokens back to real names. Residual leak (accepted at
Level 1): the same name encrypts to the same token, so Obsideo can see that two
objects share a name, never what it is; structure + sizes still show.

SCHEME (so other clients — e.g. the SDK — can interop, same account same names):
  name_key = HKDF-SHA256(ikm=data_key, salt="", info="obsideo-name-key-v1", len=64)
  token    = base64url-nopad( AES-SIV-encrypt(name_key, utf8(component), aad=none) )
  path     = "/".join(token(c) for c in path.split("/") if c)
"""

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from obsideo_core import crypto

_INFO = b"obsideo-name-key-v1"


def _name_key() -> bytes:
    # Derived fresh from the data key (cheap); stays correct if the key changes.
    return HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=_INFO).derive(crypto.data_key())


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def encrypt_name(name: str) -> str:
    return _b64e(AESSIV(_name_key()).encrypt(name.encode(), None))


def decrypt_name(token: str) -> str:
    return AESSIV(_name_key()).decrypt(_b64d(token), None).decode()


def encrypt_path(path: str) -> str:
    """Encrypt each '/'-separated component. Empty -> empty (root)."""
    return "/".join(encrypt_name(c) for c in path.split("/") if c)


def safe_decrypt_name(token: str) -> tuple[str, bool]:
    """Decrypt a listed token. Returns (name, was_encrypted). Falls back to the
    raw token for legacy clear-name objects (so listings never crash on a mixed
    account)."""
    try:
        return decrypt_name(token), True
    except Exception:
        return token, False
