"""Client-held signing identity (Ed25519).

Obsideo external accounts require a customer Ed25519 signing public key — it
authorizes destructive operations on your data (Principle 2: the network can't
delete your data without your signature). The PRIVATE half is generated here and
never leaves your machine; only the public key (obk_sig_…) is sent at signup.
"""

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

from obsideo_core import config

SIGNING_KEY_FILE = config.CONFIG_DIR / "signing.key"


def _encode_pub(raw: bytes) -> str:
    return "obk_sig_" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def get_or_create_signing_pubkey() -> str:
    """Return the Ed25519 signing public key as 'obk_sig_<43 chars>',
    generating + persisting the private key locally (0600) on first use."""
    if SIGNING_KEY_FILE.exists():
        raw = bytes.fromhex(SIGNING_KEY_FILE.read_text().strip())
        priv = Ed25519PrivateKey.from_private_bytes(raw)
    else:
        priv = Ed25519PrivateKey.generate()
        raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        config.write_secret_file(SIGNING_KEY_FILE, raw.hex())
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _encode_pub(pub)
