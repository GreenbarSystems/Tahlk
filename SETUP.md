# Tahlk — Developer Setup

## Prerequisites

1. **Node.js 18+** — for Vite and JS tooling
2. **Rust + Cargo** — https://rustup.rs (one-time install, ~5 min)
3. **Tauri prerequisites** — https://tauri.app/start/prerequisites/
   - Windows: Microsoft C++ Build Tools (or Visual Studio)
   - WebView2 (ships with Windows 11; download for older Windows)

## First Run

```powershell
# Install JS deps
npm install

# Verify the JS build
npm run build:solo       # outputs dist-solo/ with no errors

# Run the build guard
npm run test:build       # should print PASS

# Start the Tauri dev app
npm run tauri:dev        # compiles Rust + starts Vite + opens window
```

First `tauri:dev` will take 2–5 minutes to compile Rust dependencies.

## Whisper.cpp Sidecar (local transcription)

The app shells out to the `whisper-cli` binary from whisper.cpp for on-device
speech-to-text. `src-tauri/binaries/` is gitignored (binaries don't belong in
the repo), so each dev places the files locally:

1. Download the pre-compiled release for your platform from:
   https://github.com/ggml-org/whisper.cpp/releases
   (Windows x64 CPU build: `whisper-bin-x64.zip` — verified against v1.9.1.)

2. From the archive's `Release/` folder, copy `whisper-cli.exe` into
   `src-tauri/binaries/`, renamed to Tauri's sidecar convention:
   - Windows: `whisper-cpp-x86_64-pc-windows-msvc.exe`
   - macOS ARM: `whisper-cpp-aarch64-apple-darwin`
   - macOS x86: `whisper-cpp-x86_64-apple-darwin`

3. **Windows also needs the runtime DLLs** next to the renamed exe, or it
   won't start: `whisper.dll`, `ggml.dll`, `ggml-base.dll`, and every
   `ggml-cpu-*.dll` (the matching CPU backend is selected at runtime). Copy
   them from the same `Release/` folder into `src-tauri/binaries/`.

4. The Whisper model (`ggml-base.en.bin`, ~142 MB) downloads on first run via
   onboarding / Settings → Download Transcription Model. It lands in the app
   data dir (`%APPDATA%/com.tahlk.app/models/` on Windows); drop it there
   manually to skip the in-app download.

> Note: `externalBin` bundles only the exe for `tauri build`. Shipping a
> distributable still needs the DLLs added as bundle resources placed beside
> the sidecar — TODO before release. Dev (`tauri:dev`) runs fine as above.

## Anthropic API Key (note generation)

In the app's onboarding or Settings page, enter your Anthropic API key
(console.anthropic.com → API Keys). The key is stored in the local SQLite
database only — never sent to any server.

Long-term: once a HIPAA BAA is signed with Anthropic, the app will switch
to a managed key and users won't need to provide their own.

## Architecture

```
src/core/       — storage, eventBus, capabilities seam
src/scribe/     — recorder.js, transcriber.js, noteGenerator.js
src/editor/     — noteEditor.js (sign-off + SHA-256 audit chain)
src/templates/  — 5 built-in behavioral health templates
src/export/     — plain text / SimplePractice / TherapyNotes formatters
src/solo/       — Solo UX: home, encounter panel, settings, onboarding
src-tauri/      — Rust backend: SQLite KV + encounters + audio + LLM + export
```

## Privacy Architecture

- **Local-first**: all data in SQLite on the user's device
- **SHA-256 hash chain**: every note edit logged; sign-off binds to exact content
- **API key in LOCAL_ONLY storage**: stored in Rust/SQLite, never accessible from JS
- **Audio never leaves the device**: WAV written to app data dir, transcribed locally via whisper.cpp
- **Tauri CSP**: no external scripts; Anthropic API whitelisted in connect-src only

## Encryption at Rest (SQLCipher)

The local SQLite database (`tahlk.db` in the OS app-data directory) is
encrypted with SQLCipher using AES-256-CBC + HMAC-SHA512 — the file on disk
does not contain the `SQLite format 3` header and cannot be opened by
regular `sqlite3`.

### How the key is managed

- A 256-bit **Database Encryption Key (DEK)** is generated on first launch
  via the OS CSPRNG (`getrandom`) and stored in the platform secure store:
  - **macOS** → Keychain (item name `com.tahlk.app` / `db_encryption_key`)
  - **Windows** → Credential Manager (same names)
  - **Linux** → Secret Service (GNOME Keyring / KWallet, same names)
- The DEK is loaded once at startup and applied via
  `PRAGMA key = "x'<64-hex>'"` — the raw-key form bypasses PBKDF2, so
  startup is instant and the key on disk is exactly the 32 bytes we
  generated (no derivation).
- **No passphrase prompt.** The trust anchor is the OS user session; if
  someone can log in as the user and query the keychain, they can read
  the DB. This is a deliberate trade-off — a clinician forgetting a
  passphrase would be worse than the residual risk under FDE.

### Recommended complementary controls

- **Full-disk encryption is required.** FileVault (macOS) or BitLocker
  (Windows) is the primary defense against a stolen or off-hours device.
  SQLCipher only protects the DB file itself, not the OS keychain, swap,
  or crash dumps.
- **Screen-lock and short auto-lock** on the workstation. A logged-in
  session with an unlocked keychain has full DB access.
- **Do not sync the app-data directory** to iCloud Drive / OneDrive /
  Dropbox. The ciphertext is safe in transit but the sync provider
  becomes a copy of the DB the vendor's ToS may or may not allow for
  PHI — check the BAA scope. Time Machine backups of `~/Library/Application Support/`
  will contain the encrypted DB; they are usable only from a machine
  whose keychain still holds the DEK.

### Legacy database migration

If a `tahlk.db` from a pre-encryption build exists in the app-data dir,
the first launch after upgrading will:

1. Detect the plaintext file by its `SQLite format 3\0` header.
2. Copy the schema + data into a new encrypted file (`tahlk.db.encrypted`)
   via `sqlcipher_export`.
3. Verify the encrypted copy opens with the DEK.
4. Rename the plaintext file to `tahlk.db.plaintext.bak`, overwrite it
   with zeros, and unlink it. (This is best-effort on SSDs — wear
   leveling can leave recoverable fragments; FDE is what actually
   forecloses forensic recovery.)
5. Move the encrypted file into place as `tahlk.db`.

If step 5 crashes, the next launch will find both files: it refuses to
overwrite an existing encrypted DB and requires manual intervention.

### What is NOT yet encrypted

- **Audio WAV files** in the `sessions/` subdirectory of app-data. These
  are transcribed locally and deleted after signing, but on-disk between
  those two events they are plaintext. FDE covers this.
- **Session logs / crash dumps** written by the OS.
- **The sync server database** (see `server/`). BAA-gated deployment
  and server-side encryption are tracked as separate work items.

### Rotating or resetting the DEK

- **Rotation is not yet exposed in the UI.** Rekeying a SQLCipher DB
  requires `PRAGMA rekey` on an already-open connection — a follow-up
  release will add a Settings action for this.
- **To reset**: delete the `db_encryption_key` entry from the OS
  keychain AND delete `tahlk.db` from the app-data dir. Both must go —
  a keychain entry without a matching DB is harmless, but a DB without
  its key is unrecoverable.
