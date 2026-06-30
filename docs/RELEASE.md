# Release & code signing

How to produce a distributable Tahlk installer. The bundling (sidecar exe + 12
whisper DLLs + 144 MB model, co-located at the resource root) is done and
verified. **Code signing is the remaining GA gate** and needs a certificate.

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

## Drop-in B — EV hardware token or cloud signing (Azure Trusted Signing)

The private key isn't exportable, so use a custom `signCommand` instead of a
thumbprint (Tauri ≥ 2.1). Example (Azure Trusted Signing via `trusted-signing-cli`):

```json
"windows": {
  "signCommand": "trusted-signing-cli -e https://eus.codesigning.azure.net -a <account> -c <profile> %1",
  "timestampUrl": "http://timestamp.acs.microsoft.com"
}
```

`%1` is the file to sign. For a SafeNet/USB token, point `signCommand` at
`signtool` with the token CSP and supply the PIN via the token's keystore.

## CI-signed releases (recommended, reproducible)

Add a tag-triggered release job that imports the cert from a secret. Sketch:

```yaml
on: { push: { tags: ['v*'] } }
jobs:
  release:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      # import PFX from a base64 secret into the store, then set the thumbprint
      # env TAURI_SIGNING ... (or write certificateThumbprint), then:
      - run: npm ci && npm run tauri -- build --bundles nsis
      # upload Tahlk_*_x64-setup.exe as a release asset
```

Store the cert as a GitHub Actions secret (base64 PFX + password), never in the
repo. The desktop build still needs the sidecar/DLLs/model present — see SETUP.md.

## macOS (future)

Requires an Apple **Developer ID Application** cert + **notarization**
(`xcrun notarytool`). Set `APPLE_CERTIFICATE`, `APPLE_ID`, `APPLE_PASSWORD`,
`APPLE_TEAM_ID` and Tauri handles signing + notarization on `tauri build`.

## Final QA gate (cannot be skipped)

Install the produced `.exe` on a **clean Windows VM** (no dev tools, no whisper
libs on PATH) and run record → transcribe → generate → sign → export. This is
the only check that proves the sidecar resolves its DLLs and finds the model
*as installed* — bundle-layout verification is necessary but not sufficient.
