"""Deception module: fabricates believable fake content in place of any
"Access Denied" / "Authentication Failed" / "Unauthorized Access"
response, and logs every activation for internal audit purposes.
"""

from deception.content_types import DeceptionContentType
from deception.deception_engine import DeceptionEngine, DeceptionResponse
from deception.triggers import DeceptionTrigger

__all__ = [
    "DeceptionContentType",
    "DeceptionEngine",
    "DeceptionResponse",
    "DeceptionTrigger",
]
