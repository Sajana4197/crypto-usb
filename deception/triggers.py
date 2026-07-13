"""Reasons the Deception Engine may be activated.

Each member corresponds to a real failure the rest of the application
already detects (`security/` for credentials, `validation/` for
access-time checks) — the Deception Engine itself never decides
*whether* something failed, only *what to show* once it has.
"""

from __future__ import annotations

from enum import Enum


class DeceptionTrigger(str, Enum):
    WRONG_CREDENTIALS = "wrong_credentials"
    ACCESS_ALREADY_USED = "access_already_used"
    DEVICE_MISMATCH = "device_mismatch"
    METADATA_TAMPERING = "metadata_tampering"
    INTEGRITY_FAILURE = "integrity_failure"
