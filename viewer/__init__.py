"""RAM-only secure file viewer.

`viewer.interfaces` defines the contract (`ViewerBackend`,
`SecureViewSession`) between in-memory decryption and viewing.
`viewer.secure_viewer_widget.SecureViewerWidget` is the controlled
viewer that implements that contract: PDF/image/TXT rendering with
copy/export/print/edit disabled and best-effort Windows screen-capture
mitigation (`viewer.screen_capture_protection`).
"""

from viewer.interfaces import SecureViewSession, ViewerBackend
from viewer.secure_viewer_widget import SecureViewerWidget

__all__ = ["SecureViewSession", "SecureViewerWidget", "ViewerBackend"]
