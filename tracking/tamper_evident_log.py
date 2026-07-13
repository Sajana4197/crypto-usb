"""Encrypted, hash-chained storage envelope for `UsageRecord` entries.

Follows the same encrypt-then-MAC posture as `metadata.protection`
(AES-256-GCM for confidentiality, an independent HMAC-SHA256 checked
*before* decryption is attempted) — that alone is enough to detect a
*modified* stored entry, exactly like a metadata record. Usage logs
have a second threat this module also has to cover: an attacker
*deleting* or *reordering* an entry outright, which a per-entry HMAC
alone cannot catch (the remaining rows would each still verify fine on
their own).

To catch that too, every entry's HMAC is computed over the *previous*
entry's HMAC as well as its own content (`prev_hmac || nonce ||
ciphertext`) — a hash chain. The very first entry chains from a fixed
all-zero `GENESIS_HMAC`. Verifying the whole log means walking it in
order and confirming each entry's `prev_hmac` matches the previous
entry's `entry_hmac`: removing, inserting, or reordering any entry
breaks that link for everything after it, and modifying any entry's
content changes its own HMAC, which then no longer matches what the
*next* entry recorded as `prev_hmac`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

from core.logger import get_logger
from crypto import aes_cipher
from crypto.exceptions import DecryptionError
from crypto.hmac_util import HMAC_KEY_SIZE_BYTES, compute_hmac, verify_hmac
from tracking.exceptions import TrackingTamperError
from tracking.models import UsageRecord

logger = get_logger(__name__)

# HMAC-SHA256 digest size; the fixed chain root the first entry links to.
GENESIS_HMAC = b"\x00" * 32


@dataclass
class TrackingProtectionKeys:
    encryption_key: bytes
    hmac_key: bytes


def generate_tracking_keys() -> TrackingProtectionKeys:
    """Generate a fresh usage-log encryption key and HMAC key."""
    return TrackingProtectionKeys(
        encryption_key=aes_cipher.generate_fek(),
        hmac_key=os.urandom(HMAC_KEY_SIZE_BYTES),
    )


@dataclass
class ChainedLogEntry:
    """The on-disk envelope for one usage record: opaque except for the chain link."""

    nonce: bytes
    ciphertext: bytes
    prev_hmac: bytes
    entry_hmac: bytes


@dataclass
class ChainVerificationResult:
    ok: bool
    verified_count: int
    reason: Optional[str] = None


class TamperEvidentLog:
    """Seals `UsageRecord`s into, and opens/verifies them from, a hash chain."""

    def __init__(self, keys: TrackingProtectionKeys) -> None:
        self._keys = keys

    @staticmethod
    def _mac_input(prev_hmac: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        return b"|".join([prev_hmac, nonce, ciphertext])

    def seal(self, record: UsageRecord, prev_hmac: bytes = GENESIS_HMAC) -> ChainedLogEntry:
        """Encrypt `record` and chain it onto `prev_hmac` (the previous
        entry's `entry_hmac`, or `GENESIS_HMAC` for the first entry)."""
        payload = json.dumps(record.to_dict(), sort_keys=True).encode("utf-8")
        nonce, ciphertext = aes_cipher.encrypt(payload, self._keys.encryption_key)
        entry_hmac = compute_hmac(self._keys.hmac_key, self._mac_input(prev_hmac, nonce, ciphertext))

        logger.info("Sealed usage record session_id=%s into the tamper-evident log", record.session_id)
        return ChainedLogEntry(nonce=nonce, ciphertext=ciphertext, prev_hmac=prev_hmac, entry_hmac=entry_hmac)

    def verify_entry(self, entry: ChainedLogEntry) -> bool:
        """Check one entry's own HMAC, independent of its position in a chain."""
        mac_input = self._mac_input(entry.prev_hmac, entry.nonce, entry.ciphertext)
        return verify_hmac(self._keys.hmac_key, mac_input, entry.entry_hmac)

    def open(self, entry: ChainedLogEntry) -> UsageRecord:
        """Verify and decrypt `entry`. Raises `TrackingTamperError` if either fails."""
        if not self.verify_entry(entry):
            logger.warning("Usage log entry failed HMAC verification")
            raise TrackingTamperError("Usage log entry failed its integrity check")

        try:
            payload = aes_cipher.decrypt(entry.nonce, entry.ciphertext, self._keys.encryption_key)
        except DecryptionError as exc:
            raise TrackingTamperError(f"Usage log entry failed to decrypt: {exc}") from exc

        return UsageRecord.from_dict(json.loads(payload.decode("utf-8")))

    def verify_chain(self, entries: list[ChainedLogEntry]) -> ChainVerificationResult:
        """Verify every entry's HMAC and that the chain links between them are unbroken.

        Entries must be given in their original stored order. Stops at
        the first broken link or invalid HMAC and reports its index.
        """
        expected_prev = GENESIS_HMAC
        for index, entry in enumerate(entries):
            if entry.prev_hmac != expected_prev:
                reason = (
                    f"Broken chain link at entry {index}: does not follow from the "
                    "previous entry (an entry was deleted, inserted, or reordered)"
                )
                logger.warning("Usage log verification failed: %s", reason)
                return ChainVerificationResult(ok=False, verified_count=index, reason=reason)

            if not self.verify_entry(entry):
                reason = f"HMAC mismatch at entry {index}: entry content or chain link was modified"
                logger.warning("Usage log verification failed: %s", reason)
                return ChainVerificationResult(ok=False, verified_count=index, reason=reason)

            expected_prev = entry.entry_hmac

        logger.info("Usage log verified: %d entr%s intact", len(entries), "y" if len(entries) == 1 else "ies")
        return ChainVerificationResult(ok=True, verified_count=len(entries), reason=None)
