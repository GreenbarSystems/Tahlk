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
