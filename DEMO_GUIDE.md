# CryptoUSB — Step-by-Step Demonstration Guide

A full walkthrough of every feature, in demo order. Each step says what to click, what you should see, and which proposal requirement it proves. Every requirement below is fully live — no known feature gaps — but a few UI behaviors worth narrating on purpose are called out inline (e.g. Part 4.3).

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
3. Leave the **"One-time access"** checkbox unchecked for now (you'll demo it in Part 5), then click **Write Secure Container**.
4. **Expect:** a confirmation popup **and** a status line reading *"Wrote and fully verified ... — decryption round-trip and metadata integrity confirmed in memory; no plaintext was written to disk"*, **and** the file now appears in the **"Files encrypted on this device"** table below, immediately — no manual refresh needed.
5. Click **Export Key Pair for Decryption...**, set a passphrase, save the `.pem` file somewhere you can find it. **Say out loud**: without doing this step, this file can never be decrypted by anyone, including you — the app keeps no copy. (Note: the selected file clears automatically right after export, so pick the file again if you want to write another container.)

**Say out loud — how the receiver actually gets the key + passphrase:** in a real deployment this `.pem` file and its passphrase reach the receiver through **two separate, out-of-band channels** — e.g. the sender emails the file, then calls the receiver to give them the passphrase. They're deliberately never sent together: intercepting one channel alone gets an attacker nothing. The app doesn't handle this transmission at all, by design — it only guarantees the file is useless without both pieces. You're playing both roles on one machine for this demo, so you already have both; narrate the split explicitly so it doesn't look like a gap.

→ *Proves: hybrid AES+RSA encryption, unique key per file, metadata-driven storage, RAM-only round-trip verification (Requirements 4, 8, 10).*

---

## Part 4 — Receiver side: decrypt and view

**4.1 Decrypt & View (nav item)**
1. Select the USB drive.
2. **Browse Private Key File...** → pick the `.pem` you exported in 3.2, enter its passphrase, **Load Key**. **Expect:** a "Private key loaded" confirmation popup.
3. Select the container in the "Secure containers on the selected device" table.
4. **View Selected File** → the Secure Viewer opens with the real content.

**4.2 Prove the restrictions, live, deliberately**
With the viewer open:
- Try **Ctrl+C**, or right-click → **nothing happens** (context menu and clipboard are disabled).
- If you opened a PDF or image, point out the **zoom in / zoom out / fit-to-window** toolbar at the top of the viewer — content defaults to fit-to-window on open instead of native size, with manual zoom available if you need to check fine detail.
- Press **Print Screen** → the content **blanks instantly and the viewer closes itself**. This is your strongest visual beat — do it on purpose, and narrate: *"the app can't stop the OS from taking a screenshot, but it can guarantee the screenshot captures nothing and the session ends immediately."*

**4.3 Note: the key unloads itself after every view**
Closing the viewer — normally, or via a screen-capture trip — automatically clears the loaded private key and its passphrase field. A loaded key is only trusted for the single viewing session it was loaded for, by design. To view anything else, even the same file again, repeat step 4.1's browse-and-load. Don't be caught off guard live: if **View Selected File** looks greyed out after a previous view, this is why.

→ *Proves: controlled viewing environment, RAM-only decryption, copy/edit restriction, screen-capture reaction (Requirements 2, 5, 6).*

---

## Part 5 — One-time access enforcement

The Encrypt File page has a **"One-time access (file is destroyed after first successful view)"** checkbox above **Write Secure Container** — fully live, no code changes needed.

1. In **Encrypt File**, choose a fresh test file, **check the one-time-access box**, then **Write Secure Container**.
2. Go to **Decrypt & View**, browse and load your `.pem` key, select the new container, **View Selected File** — the real content shows, as normal.
3. Close the viewer. Per the note in 4.3, the key auto-unloads — **browse and load the same key again**, select the same container, **View Selected File** a second time.
4. **Expect:** the second view silently shows fake content instead of the real file — no error, no indication that anything is different. Narrate: *"the file was consumed by the first legitimate view; a second attempt — from anyone, including me — gets deception, not a denial."*

→ *Proves: one-time access enforcement (`metadata/one_time_access.py` burn logic), consistent with the deception design in Part 6.*

---

## Part 6 — Deception Module

**6.1 Wrong credentials → honeypot (always demo this one, it's fully live)**
1. Sign out (or relaunch and cancel to the login screen).
2. Enter the **wrong password** deliberately.
3. **Expect:** login proceeds normally — no "incorrect password" error. Narrate: *"the system never tells an attacker they got it wrong."*
4. Go to Decrypt & View and try to open any file.
5. **Expect:** the viewer opens but shows fake/garbage content, not the real file, not an error.

→ *Proves: Deceptive Protection Mechanism (Requirement 7) and multi-layer validation triggering deception (Requirement 12) — the flagship requirement.*

**6.2 Device mismatch / tampering (optional, needs a second USB or a hex editor — but worth doing if you have time, see the payoff below)**
- *Device mismatch*: write a container on USB A, then plug in USB B and try to open the same `.cusc` file copied there — device-binding check fails, fake content is served.
- *Tampering*: open the `.cusc` file in a hex editor and flip a few bytes in the middle, then try to view it — HMAC/integrity check fails, fake content is served.

Both are optional flourishes; 6.1 alone fully demonstrates the deception system. But if you do the tampering variant, go to **Usage Tracking** afterward (Part 7) and point at the **Tampering** column showing a real entry — the event isn't just detected and deceived in the moment, it's independently recorded to the audit log too.

---

## Part 7 — Audit & oversight pages

Now go back to **Dashboard** — the "Recent activity" feed should show your Part 6.1 attempt.

- **Deception Module** page: the wrong-credentials event you just triggered is logged here with its trigger type — this is what proves deception isn't just theoretical, it's independently auditable by whoever controls the machine, even though the attacker never saw it.
- **Usage Tracking** page: full access log (who, when, granted/denied) + **Verify Log Integrity** button — click it to show the HMAC hash-chain check passing. Its **Tampering** column stays at 0 unless you did the optional 6.2 tampering demo — that's correct, not a bug: it only counts genuine metadata/integrity failures, never device mismatches or reused one-time files.
- **Access Security** page: account lockout state (failed-attempt counter, lockout status).
- **Metadata** page: per-file integrity validation status.

→ *Proves: usage monitoring, metadata-driven access control, audit trail (Requirements 3, 10, 15, 16).*

---

## Part 8 — Settings

Theme toggle (dark/light) and Change Password — quick, show if time allows, not critical to the security story.

---

## Part 9 — Under-the-hood proof (keep in your back pocket, don't lead with it)

If a supervisor pushes on "how do we know this really works, not just the UI":

1. **Full test suite**: run `.venv/Scripts/python.exe -m pytest -q` → 769 tests passing, 0 failed, `ruff check .` clean.
2. **Database is genuinely encrypted**: show the raw `data/crypto_usb.db` file's first bytes in a hex viewer — random ciphertext, not the plaintext `SQLite format 3` header every normal SQLite file starts with.
3. **Frozen build works too**, not just `python main.py`: mention the app was verified running from a PyInstaller-built `.exe`, with the SQLCipher native library correctly bundled.

---

## Honest caveats — have answers ready, don't hide these

- **Screen-capture protection is Windows-only and best-effort** (`WDA_EXCLUDEFROMCAPTURE`/`WDA_MONITOR`) — no OS gives a desktop app a way to guarantee this against every capture method (e.g. a phone camera). Documented, not hidden.
- **The SQLCipher database key is a local machine file, not derived from the user's password** — it can't be, without deadlocking login (you need to open the DB to check the password before you have a password to derive a key from). The credential-derived key from Phase 21 still protects the specific metadata/tracking values on top of this.
- **The decrypt-page private key unloads after every view** (see 4.3) — intentional session-scoping, not a bug, but it means Part 5's two-view demo needs the key reloaded between attempts. Don't skip narrating why if a supervisor notices the button greying out.
