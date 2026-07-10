# Release & code signing

How to produce a distributable Tahlk installer. The bundling (sidecar exe + 12
whisper DLLs + 144 MB model, co-located at the resource root) is done and
verified. Code signing infrastructure (Azure Trusted Signing account +
`release.yml`, below) is wired up — **the remaining GA gate is running the
first signed build and the clean-VM QA pass**, not acquiring a certificate.

## Build the installer

```powershell
# from repo root; requires the whisper sidecar + DLLs in src-tauri/binaries/
# and the model at src-tauri/resources/ggml-base.en.bin (both gitignored, see SETUP.md)
npm run tauri -- build --bundles nsis
# -> src-tauri/target/release/bundle/nsis/Tahlk_<version>_x64-setup.exe
```

## Signing is pre-staged

`tauri.conf.json` → `bundle.windows` already sets `digestAlgorithm` and
`timestampUrl`. These are **inert without a certificate** — Tauri only signs
when a thumbprint or sign command is present, so the unsigned build works today.
Adding the cert is a one-line (or one-secret) change below.

## Choose a certificate

| Type | Cost | SmartScreen | Notes |
|---|---|---|---|
| **OV** (Organization Validated) | ~$200–400/yr | Warns until reputation builds | Cheapest; reputation accrues over downloads |
| **EV** (Extended Validation) | ~$300–700/yr | **Instant trust** | Hardware token or cloud (Azure Trusted Signing). **Recommended for a medical app.** |

## Drop-in A — cert installed in the Windows cert store (OV, or EV-in-store)

Add the thumbprint to `tauri.conf.json` → `bundle.windows`:

```json
"windows": {
  "certificateThumbprint": "PASTE_SHA1_THUMBPRINT_HERE",
  "digestAlgorithm": "sha256",
  "timestampUrl": "http://timestamp.digicert.com"
}
```

Get the thumbprint: `Get-ChildItem Cert:\CurrentUser\My | Select Thumbprint, Subject`.
That's the entire change — rebuild and the installer is signed + timestamped.

## Drop-in B — EV hardware token or cloud signing (Azure Artifact Signing)

The private key isn't exportable, so use a custom `signCommand` instead of a
thumbprint (Tauri ≥ 2.1). Example (Azure Artifact Signing, formerly "Trusted
Signing," via `artifact-signing-cli`):

```json
"windows": {
  "signCommand": "artifact-signing-cli -e https://eus.codesigning.azure.net -a <account> -c <profile> %1",
  "timestampUrl": "http://timestamp.acs.microsoft.com"
}
```

> **Naming note:** Microsoft renamed the service from "Trusted Signing" to
> "Artifact Signing." The RBAC role is now **"Artifact Signing Certificate
> Profile Signer"** and the CLI tool is `artifact-signing-cli` (same
> maintainer/repo as the older `trusted-signing-cli`, which is deprecated but
> still calls the old API surface — using it against an account whose role
> was assigned under the new name will 403 even with a correct role
> assignment). Use `artifact-signing-cli`.

`%1` is the file to sign. For a SafeNet/USB token, point `signCommand` at
`signtool` with the token CSP and supply the PIN via the token's keystore.

## CI-signed releases

`.github/workflows/release.yml` is a tag-triggered (`v*`) Windows build that:

1. Validates the four `AZURE_*` signing secrets (GUID format + whitespace
   check) before installing any toolchain, so a bad secret fails in seconds
   instead of after a 10+ minute Rust compile.
2. Runs the same lock gates as `ci.yml` (`test:build`, `test:js`).
3. Downloads the whisper.cpp sidecar/DLLs and the `ggml-base.en.bin` model
   from the same public URLs a developer uses locally (see SETUP.md) — these
   still aren't hosted anywhere else, so CI fetches them fresh on every run.
4. Installs `artifact-signing-cli`, self-tests it (`--help` + exit code),
   then builds with `--config src-tauri/tauri.release.conf.json` (Drop-in B
   above) and `--verbose` so a real signing failure surfaces inline.
5. Independently verifies the Authenticode signature on the produced
   installer via `Get-AuthenticodeSignature` — never trusts the build log's
   claim alone.
6. Opens a **draft** GitHub Release with the signed installer attached. A
   human runs the clean-Windows-VM QA pass below and publishes the draft
   manually — nothing auto-publishes.

The Artifact Signing resource is `ryanmoore-codesign` / profile `default`,
authenticated via the `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` /
`AZURE_CLIENT_SECRET` / `AZURE_SUBSCRIPTION_ID` repo secrets — never in the repo.

**Known gaps, tracked as follow-ups, not blockers:** the whisper artifacts are
re-downloaded from public URLs on every release run rather than pinned to
internal storage (fine for now — they're static upstream releases — but worth
mirroring if `ggml-org/whisper.cpp` or the HuggingFace model URL ever moves).
macOS is not built here yet (see below).

## Getting fixes to clinicians (updates)

Tahlk ships **no in-app auto-updater**, and that is a deliberate choice for now,
not an oversight. The Tauri updater plugin is a real subsystem: it needs its own
**update-signing keypair** (separate from the code-signing cert), a **hosted
update manifest + artifact endpoint**, and `createUpdaterArtifacts` wired into
the bundle. Standing that up before we even have a code-signing certificate — the
GA gate above — would be premature. Until it's warranted:

- **Distribution is manual.** A new version is a new signed installer; clinicians
  re-download and re-run it. Installing over an existing install preserves the
  local encrypted DB (it lives in the app data dir, not the install dir).
- **Bump `version` in `tauri.conf.json` and `src-tauri/Cargo.toml` together** so
  the About screen and the installer file name agree.

Add the updater only when there are enough installs that manual re-download is a
real support burden — at which point the keypair + a static manifest on any
object store is a small, well-trodden addition. Track it as a follow-up, not a
blocker.

## Support diagnostics: the crash/error log

The desktop app writes a rolling log to the OS log directory via
`tauri-plugin-log` (wired first in `src-tauri/src/lib.rs::run`):

| OS | Path |
|---|---|
| Windows | `%LOCALAPPDATA%\com.tahlk.app\logs\` |
| macOS | `~/Library/Logs/com.tahlk.app/` |
| Linux | `~/.local/share/com.tahlk.app/logs/` |

This exists because a GUI launch has no attached terminal — without it, a
`panic!` (e.g. the fail-closed DB-open guard when the keychain is locked or the
DEK is corrupt) and every `eprintln!` diagnostic would vanish, leaving a broken
install with nothing to send support. A panic hook routes crashes into this file
before the process aborts. **The log is metadata/diagnostics only — it must never
contain PHI**; if a future log line would include transcript or note text,
redact at the call site, matching the server-side redaction precedent (S3).

When triaging a clinician report, the first ask is: *"send us the newest file in
that folder."*

## macOS (future)

Requires an Apple **Developer ID Application** cert + **notarization**
(`xcrun notarytool`). Set `APPLE_CERTIFICATE`, `APPLE_ID`, `APPLE_PASSWORD`,
`APPLE_TEAM_ID` and Tauri handles signing + notarization on `tauri build`.

## Final QA gate (cannot be skipped)

Install the produced `.exe` on a **clean Windows VM** (no dev tools, no whisper
libs on PATH) and run record → transcribe → generate → sign → export. This is
the only check that proves the sidecar resolves its DLLs and finds the model
*as installed* — bundle-layout verification is necessary but not sufficient.
