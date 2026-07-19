"""Shared pytest configuration.

Forces Qt's offscreen platform plugin so the GUI test suite runs
headlessly without flashing windows or requiring a display.
"""

import gc
import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def rsa_keypair_fixture():
    """A single RSA-4096 key pair reused across tests that don't test generation itself.

    RSA-4096 generation is expensive; tests that specifically exercise
    `rsa_keypair.generate_rsa_keypair()` still call it directly.
    """
    from crypto import rsa_keypair

    return rsa_keypair.generate_rsa_keypair()


@pytest.fixture(scope="session")
def other_rsa_keypair_fixture():
    """A second, distinct RSA-4096 key pair for wrong-key negative tests."""
    from crypto import rsa_keypair

    return rsa_keypair.generate_rsa_keypair()


@pytest.fixture(autouse=True)
def _isolate_vault_key_path(tmp_path, monkeypatch):
    """Redirect the SQLCipher file key (Phase 23) into this test's own
    `tmp_path`, never the real project's `data/.vault_key`.

    `utils.paths.get_vault_key_path()` is not parameterized by whatever a
    test monkeypatches `get_database_path()` to — it always resolves
    under the real project data directory unless overridden. Any test
    that constructs a real `DatabaseManager` would otherwise read/write
    the actual installation's file-encryption key, leaking state between
    test runs and polluting the real application data directory. Applied
    to every test (not just the ones that need it) since it is a no-op
    for tests that never touch `DatabaseManager`.
    """
    monkeypatch.setattr("database.file_key.get_vault_key_path", lambda: tmp_path / ".vault_key")


@pytest.fixture(autouse=True)
def _reset_global_excepthook():
    """`app.error_handling.install_excepthook()` is a real, permanent
    `sys.excepthook` assignment gated by a module-level `_installed` flag
    with no teardown of its own. Once any test calls the real
    `app.main.bootstrap()` (tests/test_app_main_auth.py does, several
    times), every *subsequent* test in this same pytest process runs
    with the app's "show an error dialog" hook wired into
    `sys.excepthook` — including tests that have nothing to do with
    error handling.

    That leak, combined with `QMessageBox.critical()` pumping its own
    nested Qt event loop (see `_collect_garbage_after_test` below for
    the other half), turned a single stray exception from an unrelated,
    long-finished test into unbounded mutual recursion between
    `_handle` and `_show_error_dialog` deep inside
    tests/test_decryption_page.py — the single-process full-suite hang.
    `tests/test_error_handling.py` already knew a leak was *possible*
    (see its own `_restore_excepthook` fixture's comment) but only
    guarded its own file; this guards every test.

    Also resets `_dialog_open` — the reentrancy guard added alongside
    `_installed` to stop a persistent fault (e.g. a pulled USB drive)
    from stacking multiple modal error dialogs in production. It is the
    same class of cross-test leak: a test that raises inside a mocked
    `QMessageBox.critical` without reaching `_show_error_dialog`'s
    `finally`, or one that sets it manually to test the guard itself,
    would otherwise leave every later test's real exceptions logged but
    silently never shown.
    """
    yield
    sys.excepthook = sys.__excepthook__
    import app.error_handling as error_handling

    error_handling._installed = False
    error_handling._dialog_open = False


@pytest.fixture(autouse=True)
def _collect_garbage_after_test():
    """Every page that auto-refreshes on a timer (Dashboard, Metadata,
    Usage Tracking, Deception Module, Access Security, Device
    Validation, Encrypt File, Decrypt & View) does
    `self._refresh_timer = QTimer(self)` then
    `self._refresh_timer.timeout.connect(self.refresh)`. That connection
    holds a bound method (`self.refresh`), which holds a strong
    reference back to `self` — a genuine Python reference cycle (page
    -> timer -> bound method -> page) that plain refcounting can never
    collect; only the cyclic garbage collector can, on its own
    non-deterministic schedule.

    Most page-construction tests never explicitly close or stop the
    page they build, so left alone these become "zombies": unreachable
    from any test but still alive, with a real `QTimer` still ticking.
    Any later test that pumps the Qt event loop (e.g.
    `ui.widgets.busy.progress_dialog`'s `QApplication.processEvents()`)
    can make one of these zombies' `refresh()` fire against a
    repository/DB connection some earlier test's fixture has since
    closed, raising an exception with nowhere expected to go.

    Forcing a collection after every test reclaims these cycles
    immediately instead of letting the population grow across the
    whole session, so a zombie's stale callback essentially never gets
    the chance to fire in the first place.
    """
    yield
    gc.collect()
