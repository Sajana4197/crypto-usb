# Overrides `_pyinstaller_hooks_contrib`'s `hook-usb.py`, which is written
# for the third-party PyUSB library (also a top-level package named
# `usb`) and imports its internals to enumerate backends. This project's
# own top-level `usb/` package (USB device detection and secure storage)
# is a same-named but entirely unrelated local package — PyUSB is not a
# dependency here — so the contrib hook fails at build time trying to
# import a PyUSB module that doesn't exist in this environment.
#
# An empty hook module (this file) shadows the contrib one for any
# `hookspath` that lists this directory before PyInstaller's own search
# path, and requires nothing further: our `usb` package needs no special
# PyInstaller handling, it's ordinary pure-Python application code that
# gets picked up by the normal import analysis regardless.
