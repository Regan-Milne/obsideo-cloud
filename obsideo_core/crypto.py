"""Account-level AES-256-GCM encryption for the general CLI.

One data key per account, held locally at ~/.obsideo/data.key. Every file is
encrypted with that key and a fresh random nonce (prepended). Any file the
account uploaded can be decrypted with this one key, which is what makes
browse/download/sync work across machines — copy this key to a new machine and
everything is readable.

This differs from the mlvault extension's per-run keys (immutable ML bundles); a
general file store wants one stable key. Lose the key, lose the data — by design.
Back it up alongside your credentials.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from obsideo_core import config

DATA_KEY_FILE = config.CONFIG_DIR / "data.key"


def data_key() -> bytes:
    """Load or generate the 32-byte account data key."""
    env = os.environ.get("OBSIDEO_DATA_KEY", "").strip()
    if env:
        return bytes.fromhex(env)
    if DATA_KEY_FILE.exists():
        return bytes.fromhex(DATA_KEY_FILE.read_text().strip())
    key = os.urandom(32)
    config.write_secret_file(DATA_KEY_FILE, key.hex())
    return key


def encrypt(data: bytes) -> bytes:
    """AES-256-GCM. Returns nonce(12) + ciphertext+tag."""
    key = data_key()
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt(blob: bytes) -> bytes:
    """Inverse of encrypt. Raises on auth failure / wrong key."""
    key = data_key()
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


def data_key_backup_hint() -> str:
    return f"OBSIDEO_DATA_KEY={data_key().hex()}"
