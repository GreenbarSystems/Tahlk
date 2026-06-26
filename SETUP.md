# Greenbar Note — Developer Setup

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
npm run build:solo       # should output dist-solo/ with no errors

# Run the build guard
npm run test:build       # should print PASS

# Start the Tauri dev app
npm run tauri:dev        # compiles Rust + starts Vite + opens window
```

First `tauri:dev` will take 2–5 minutes to compile Rust dependencies.

## Whisper.cpp Sidecar (local transcription)

The app ships with a whisper.cpp sidecar binary for local speech-to-text.
You need to provide the pre-compiled binary:

1. Download `whisper.cpp` for your platform from:
   https://github.com/ggerganov/whisper.cpp/releases

2. Rename to match Tauri's sidecar naming convention and place in:
   - Windows: `src-tauri/binaries/whisper-cpp-x86_64-pc-windows-msvc.exe`
   - macOS ARM: `src-tauri/binaries/whisper-cpp-aarch64-apple-darwin`
   - macOS x86: `src-tauri/binaries/whisper-cpp-x86_64-apple-darwin`

3. The Whisper model (ggml-base.en.bin, 142 MB) is downloaded on first run
   via Settings → Download Transcription Model.

## Anthropic API Key (note generation)

In the app's onboarding or Settings page, enter your Anthropic API key
(console.anthropic.com → API Keys). The key is stored in the local SQLite
database only — never sent to Greenbar servers.

Long-term: once a HIPAA BAA is signed with Anthropic, the app will switch
to a managed key and users won't need to provide their own.

## Architecture

```
src/core/       — storage, eventBus, capabilities (from Greenbar Clearing)
src/scribe/     — recorder.js, transcriber.js, noteGenerator.js
src/editor/     — noteEditor.js (sign-off + SHA-256 chain)
src/templates/  — 5 built-in behavioral health templates
src/export/     — plain text / SimplePractice / TherapyNotes formatters
src/solo/       — Solo UX: home, encounter panel, settings, onboarding
src-tauri/      — Rust backend: SQLite KV + encounters + audio + LLM + export
```

## Privacy Infrastructure (carried from Greenbar Clearing)

- **Local-first**: all data in SQLite on the user's device
- **SHA-256 hash chain**: every note edit logged; sign-off binds to exact content
- **API key in LOCAL_ONLY KV**: never accessible from JS (stored in Rust)
- **Audio never leaves the device**: WAV written to app data dir, transcribed locally
- **Tauri CSP**: no external scripts; Anthropic API whitelisted in connect-src
