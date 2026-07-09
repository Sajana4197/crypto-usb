"""Hybrid AES-256-GCM + RSA-OAEP (ECC-ready) encryption engine and key management.

`key_wrapper.KeyWrapper` is the abstraction boundary: `key_manager` and
`file_encryptor` only ever talk to that interface, so an ECC-based
wrapper can be added later without touching either of them.
"""
