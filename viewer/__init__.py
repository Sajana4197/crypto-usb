"""RAM-only secure file viewer.

`viewer.interfaces` defines the contract (`ViewerBackend`,
`SecureViewSession`) between in-memory decryption and viewing. The
actual rendering UI that implements `ViewerBackend` is implemented in
a later phase.
"""

from viewer.interfaces import SecureViewSession, ViewerBackend

__all__ = ["SecureViewSession", "ViewerBackend"]
