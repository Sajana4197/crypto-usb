# CryptoUSB — Step-by-Step Demonstration Guide

A full walkthrough of every feature, in demo order. Each step says what to click, what you should see, and which proposal requirement it proves. Two known gaps are called out explicitly (marked **⚠ GAP**) so you're never surprised live.

---

## 0. Before you start

- [ ] Delete/rename any old local database (`data/crypto_usb.db*` and `data/.vault_key`) so you demo a clean first-run registration, not a leftover account.
- [ ] Have **two files** ready to encrypt (one you'll view normally, one you'll deliberately corrupt later for the tampering demo).
- [ ] Have **one removable USB drive** plugged in (two if you want to demo device-binding mismatch — optional, see Part 6).
- [ ] Know your test-suite command (`.venv/Scripts/python.exe -m pytest -q`) in case a supervisor asks for proof rather than a click-through.

---

## Part 1 — Registration & Authentication

**1.1 First launch → Create Account**
Launch the app. Since no account exists yet, the dialog title reads "Create Account". Pick **Password** (the radio button default) or **Private Key**.

- *Password path*: enter a password (min 8 characters) + confirm, click **Create Account**.
- *Private Key path*: enter a passphrase + confirm, click **Generate Key Pair && Choose Save Location...** (RSA-4096 generated live), then **Create Account**.

**Expect:** a recovery code is shown once, on screen, with an explicit "save this now" warning — it is never shown again. → *Proves: secure credential storage (scrypt password hashing / challenge-response key auth), one-time-reveal recovery code.*

**1.2 Restart the app → Sign In**
Close and relaunch. The dialog title now reads "Sign In" (it detected your account). Log in with the credentials you just created.

---

## Part 2 — Dashboard

Land on **Dashboard** after login.

- **Stat cards**: Protected Files, Registered Accounts, Deception Triggers, Tracking Log Entries (+ integrity status) — all live counts pulled from the real repositories, not hardcoded.
- **Recent activity** feed — currently empty on a fresh account; you'll come back here after Part 3-6 to show it fill up.
- **Quick actions**: Encrypt File / Decrypt File / Validate Device — jump straight to those pages.

→ *Proves: usage monitoring and audit visibility exist as a first-class surface, not buried logs.*

---

## Part 3 — Sender side: validate a device, then encrypt

**3.1 Device Validation (nav item)**
This page is pure device health-checking now — no file/encryption controls live here.

1. Your USB drive should already be listed (the table auto-refreshes; **Refresh Devices** forces it).
2. Select it, click **Validate Selected Device**.
3. **Expect:** a green checklist — ✓ Attached, ✓ Removable, ✓ Writable, ✓ Sufficient Space.

→ *Proves: multi-check device validation independent of the write path.*

**3.2 Encrypt File (nav item) — the real sender workflow**
1. Select the same USB drive in this page's own device table.
2. **Choose File...** → pick your first test file.
3. **Write Secure Container**.
4. **Expect:** a status line reading *"Wrote and fully verified ... — decryption round-trip and metadata integrity confirmed in memory; no plaintext was written to disk"*, **and** the file now appears in the **"Files encrypted on this device"** table below, immediately — no manual refresh needed.
5. Click **Export Key Pair for Decryption...**, set a passphrase, save the `.pem` file somewhere you can find it. **Say out loud**: without doing this step, this file can never be decrypted by anyone, including you — the app keeps no copy.

→ *Proves: hybrid AES+RSA encryption, unique key per file, metadata-driven storage, RAM-only round-trip verification (Requirements 4, 8, 10).*

---

## Part 4 — Receiver side: decrypt and view

**4.1 Decrypt & View (nav item)**
1. Select the USB drive.
2. **Browse Private Key File...** → pick the `.pem` you exported in 3.2, enter its passphrase, **Load Key**.
3. Select the container in the "Secure containers on the selected device" table.
4. **View Selected File** → the Secure Viewer opens with the real content.

**4.2 Prove the restrictions, live, deliberately**
With the viewer open:
- Try **Ctrl+C**, or right-click → **nothing happens** (context menu and clipboard are disabled).
- Press **Print Screen** → the content **blanks instantly and the viewer closes itself**. This is your strongest visual beat — do it on purpose, and narrate: *"the app can't stop the OS from taking a screenshot, but it can guarantee the screenshot captures nothing and the session ends immediately."*

→ *Proves: controlled viewing environment, RAM-only decryption, copy/edit restriction, screen-capture reaction (Requirements 2, 5, 6).*

---

## Part 5 — One-time access enforcement

**⚠ GAP:** there is currently no UI checkbox to mark a file "one-time access" — `UsagePolicy.one_time_access` defaults to `False` and `EncryptionPage` never sets it. You have two honest options for this requirement:

- **Option A (recommended if time allows):** ask me to add the checkbox to the Encrypt File write panel before your review — it's a small change, the service layer already supports it (`store_file(..., usage_policy=...)`).
- **Option B (no code changes):** don't demo it live. Instead say: *"one-time enforcement is implemented and covered by automated tests"* and show `tests/test_one_time_access_enforcer.py` passing, or open `metadata/one_time_access.py` briefly to show the burn logic.

If Option A is done before your review, the live steps are: enable the checkbox in 3.2 before writing, then repeat Part 4's view steps twice on the same file — the second view shows fake content instead of the real file, silently, with no error.

---

## Part 6 — Deception Module

**6.1 Wrong credentials → honeypot (always demo this one, it's fully live)**
1. Sign out (or relaunch and cancel to the login screen).
2. Enter the **wrong password** deliberately.
3. **Expect:** login proceeds normally — no "incorrect password" error. Narrate: *"the system never tells an attacker they got it wrong."*
4. Go to Decrypt & View and try to open any file.
5. **Expect:** the viewer opens but shows fake/garbage content, not the real file, not an error.

→ *Proves: Deceptive Protection Mechanism (Requirement 7) and multi-layer validation triggering deception (Requirement 12) — the flagship requirement.*

**6.2 Device mismatch / tampering (optional, needs a second USB or a hex editor)**
- *Device mismatch*: write a container on USB A, then plug in USB B and try to open the same `.cusc` file copied there — device-binding check fails, fake content is served.
- *Tampering*: open the `.cusc` file in a hex editor and flip a few bytes in the middle, then try to view it — HMAC/integrity check fails, fake content is served.

Both are optional flourishes; 6.1 alone fully demonstrates the deception system.

---

## Part 7 — Audit & oversight pages

Now go back to **Dashboard** — the "Recent activity" feed should show your Part 6.1 attempt.

- **Deception Module** page: the wrong-credentials event you just triggered is logged here with its trigger type — this is what proves deception isn't just theoretical, it's independently auditable by whoever controls the machine, even though the attacker never saw it.
- **Usage Tracking** page: full access log (who, when, granted/denied) + **Verify Log Integrity** button — click it to show the HMAC hash-chain check passing.
- **Access Security** page: account lockout state (failed-attempt counter, lockout status).
- **Metadata** page: per-file integrity validation status.

→ *Proves: usage monitoring, metadata-driven access control, audit trail (Requirements 3, 10, 15, 16).*

---

## Part 8 — Settings

Theme toggle (dark/light) and Change Password — quick, show if time allows, not critical to the security story.

---

## Part 9 — Under-the-hood proof (keep in your back pocket, don't lead with it)

If a supervisor pushes on "how do we know this really works, not just the UI":

1. **Full test suite**: run `.venv/Scripts/python.exe -m pytest -q` → 713+ tests passing.
2. **Database is genuinely encrypted**: show the raw `data/crypto_usb.db` file's first bytes in a hex viewer — random ciphertext, not the plaintext `SQLite format 3` header every normal SQLite file starts with.
3. **Frozen build works too**, not just `python main.py`: mention the app was verified running from a PyInstaller-built `.exe`, with the SQLCipher native library correctly bundled.

---

## Honest caveats — have answers ready, don't hide these

- **Screen-capture protection is Windows-only and best-effort** (`WDA_EXCLUDEFROMCAPTURE`/`WDA_MONITOR`) — no OS gives a desktop app a way to guarantee this against every capture method (e.g. a phone camera). Documented, not hidden.
- **The SQLCipher database key is a local machine file, not derived from the user's password** — it can't be, without deadlocking login (you need to open the DB to check the password before you have a password to derive a key from). The credential-derived key from Phase 21 still protects the specific metadata/tracking values on top of this.
- **One-time access has no UI toggle yet** (see Part 5) — implemented and tested, not yet exposed in the sender UI.
