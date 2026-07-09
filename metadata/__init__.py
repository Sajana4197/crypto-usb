"""Secure metadata-driven access control.

Encrypted, HMAC-protected `FileMetadata` records (owner, wrapped key,
access count, expiry, device binding, integrity hash, usage policy)
persisted to SQLite and governed by `MetadataController`. USB
packaging and device validation are implemented in later phases.
"""
