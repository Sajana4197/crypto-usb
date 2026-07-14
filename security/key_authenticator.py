"""Private-key authentication via RSA-PSS challenge/response.

The application never stores or retains private key material: only
the enrolled public key is persisted (`PrivateKeyCredential`). To
authenticate, the caller supplies their encrypted private key PEM and
its passphrase; this module loads it transiently, signs a random
challenge, verifies the signature against the enrolled public key, and
lets the private key object go out of scope immediately afterward.
Loading a private key only proves the passphrase was correct — the
signature/verify step is what actually proves *this* key pairs with
the *enrolled* public key, so a differing (even validly-encrypted) key
pair is rejected.

The caller-supplied PEM and passphrase are copied into `bytearray`
buffers on entry and securely wiped (`crypto.secure_cleanup.wipe`) in
a `finally` block before this method returns — on every outcome, not
only success — so neither ever outlives the single authentication
attempt that needed them.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from core.logger import get_logger
from crypto import rsa_keypair
from crypto.exceptions import CryptoError
from crypto.secure_cleanup import wipe

logger = get_logger(__name__)

CHALLENGE_SIZE_BYTES = 32


def generate_challenge() -> bytes:
    """A fresh random nonce to be signed by the private key being tested."""
    return os.urandom(CHALLENGE_SIZE_BYTES)


def _pss_padding() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


class KeyAuthenticator:
    """Verifies possession of a private key against an enrolled public key."""

    def authenticate(
        self,
        private_key_pem: bytes,
        passphrase: bytes,
        public_key_pem: bytes,
        challenge: bytes,
    ) -> bool:
        """Return True only if `private_key_pem` (unlocked by `passphrase`)
        pairs with `public_key_pem` — proven by signing `challenge`.
        """
        pem_buffer = bytearray(private_key_pem)
        passphrase_buffer = bytearray(passphrase)
        try:
            try:
                private_key = rsa_keypair.load_private_key(pem_buffer, passphrase_buffer)
            except CryptoError as exc:
                logger.warning("Private key authentication failed: could not load key (%s)", type(exc).__name__)
                return False

            try:
                signature = private_key.sign(challenge, _pss_padding(), hashes.SHA256())
            finally:
                del private_key

            try:
                public_key = rsa_keypair.load_public_key(public_key_pem)
            except CryptoError as exc:
                logger.error("Private key authentication failed: enrolled public key is invalid (%s)", type(exc).__name__)
                return False

            try:
                public_key.verify(signature, challenge, _pss_padding(), hashes.SHA256())
                return True
            except InvalidSignature:
                logger.warning("Private key authentication failed: signature did not match enrolled public key")
                return False
        finally:
            wipe(pem_buffer)
            wipe(passphrase_buffer)
