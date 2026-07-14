# No-op runtime hook. Overrides `_pyinstaller_hooks_contrib`'s
# `pyi_rth_usb.py`, which unconditionally does `import usb.backend...`
# assuming any bundled top-level `usb` package is the third-party PyUSB
# library. This project's own `usb/` package (USB device detection) has
# no `backend` submodule and needs no runtime hook at all — see
# `packaging/pyinstaller_hooks/hook-usb.py` for the matching build-time
# hook override, and `packaging/crypto_usb.spec` for how this directory
# is wired in via `hookspath`.
