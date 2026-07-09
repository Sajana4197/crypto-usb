"""Shared pytest configuration.

Forces Qt's offscreen platform plugin so the GUI test suite runs
headlessly without flashing windows or requiring a display.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
