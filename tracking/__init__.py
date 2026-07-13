"""Usage monitoring and access tracking.

`tracking.models.UsageRecord` is one tracked session (user, machine ID,
USB ID, file ID, login/open/close times, duration, authentication and
validation results, screen-capture attempts, tampering events).
`tracking.tracking_service.UsageTracker` builds one across a session's
lifecycle. `tracking.tamper_evident_log.TamperEvidentLog` encrypts and
hash-chains records before `tracking.repository.TrackingRepository`
appends them to SQLite — any modified, deleted, inserted, or reordered
entry is detectable via `UsageTracker.verify_log_integrity`.
"""

from tracking.models import UsageRecord
from tracking.repository import TrackingRepository
from tracking.tamper_evident_log import (
    ChainedLogEntry,
    ChainVerificationResult,
    TamperEvidentLog,
    TrackingProtectionKeys,
    generate_tracking_keys,
)
from tracking.tracking_service import UsageTracker

__all__ = [
    "ChainVerificationResult",
    "ChainedLogEntry",
    "TamperEvidentLog",
    "TrackingProtectionKeys",
    "TrackingRepository",
    "UsageRecord",
    "UsageTracker",
    "generate_tracking_keys",
]
