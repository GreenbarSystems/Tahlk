# Tahlk — Accepted Residual Risk & Disclosure Requirements

**Status:** Active compliance record
**Applies to:** Solo tier (`src/group/` is out of scope — separate architecture, separate ADR 0001 isolation)
**As of commit:** `065b7ff`
**Source audit:** Full plaintext-PHI-at-rest sweep of `src-tauri/src/*.rs` and the frontend storage/telemetry layers (see prior audit report and the two remediation commits below).
**Prior remediation already shipped:**
- `0e32611` — session audio encrypted at rest (AES-256-GCM)
- `065b7ff` — log-file PHI guardrail (CI static check + `log_safety.rs` redaction wrapper)
- `a607490` — export dialog disclosure copy (Item 1's in-product disclosure requirement, below)

This document formally closes the two remaining audit items that are **not** code defects — they are either a user-directed action working as designed, or an inherent, already-mitigated side effect of shelling out to an external transcription binary. Both are accepted as residual risk under the conditions below. This is the paper trail for that decision.

---

## Item 1 — Patient note export (PDF / TXT) is not encrypted, by design

### What it is

`export_note_to_file` and `export_note_pdf_to_file` (`src-tauri/src/export.rs`) write full clinical note content — unencrypted — to a location the **provider explicitly chooses** via the OS's native Save-As dialog. This is user-initiated egress, not a background or silent write: the user must actively choose "Export" and pick a destination for every single export.

### Why this is accepted, not remediated in code

HIPAA's at-rest encryption requirement (§164.312(a)(2)(iv)) governs data the **application** is responsible for storing. Once a provider deliberately exports a note to their own filesystem — functionally identical to printing a note, saving a PDF from any EHR, or exporting a chart to a USB drive — responsibility for that copy's security transfers to the provider's own endpoint security posture (full-disk encryption, workstation policy, physical security). This is a standard, expected boundary in HIPAA-context software and is not something Tahlk can control after the file leaves the app's managed storage.

### Disclosure requirement (what MUST exist for this to remain an accepted risk)

For this item to stay in "accepted risk" status rather than "open gap," **both** of the following must be true at all times:

1. **In-product disclosure.** The export flow (dialog copy, tooltip, or a one-time confirmation) must state, in substance: *"Exported files are not encrypted by Tahlk. Save exports only to an encrypted device or secure location — you are responsible for protecting this file once it leaves the app."* This applies to both `export_note_to_file` (.txt) and `export_note_pdf_to_file` (.pdf).
   **Shipped in `a607490`:** persistent helper text (`.export-disclosure` in `src/solo/encounter/template.js`) under the export controls in both the draft and signed states, plus a matching `title` tooltip on the Save File / Save as PDF buttons. Shown on every render, not a dismissible one-time modal — the risk applies to every export, not just the first.
2. **Compliance documentation.** Tahlk's HIPAA risk assessment / Business Associate context documentation must name this exact behavior (unencrypted, provider-directed export) as a known, accepted data flow — not omit it.
   **Shipped:** [`docs/security/hipaa-risk-assessment.md`](docs/security/hipaa-risk-assessment.md), Flow C, names this exact behavior, its mitigations, and its ongoing conditions.

If either of these is missing, this item reverts to an **open gap**, not an accepted risk — see the checklist below.

---

## Item 2 — Transcript & audio scratch files exist as plaintext during transcription

### What it is

`transcribe_audio` (`src-tauri/src/whisper.rs`) shells out to the bundled whisper.cpp sidecar, which is an external process that can only read/write real files on disk — it cannot accept in-memory buffers or piped bytes for this build. Because of that constraint:

- Session audio is decrypted to a transient plaintext `.wav` (guarded by the `WavCleanup` RAII struct, `src-tauri/src/whisper.rs:47`).
- The sidecar's transcript output lands as a transient plaintext `.txt` (guarded by the `TxtCleanup` RAII struct, `src-tauri/src/whisper.rs:28`).

Both are the actual patient-conversation content — the transcript scratch file in particular is arguably the single most sensitive artifact anywhere in the pipeline, since it is the conversation in text form.

### Why this is accepted as residual risk, not fully eliminated

This is inherent to integrating a file-based external CLI tool; eliminating it entirely would require either a named-pipe/FIFO-based rewrite of the whisper integration (Unix-only, no reliable Windows/macOS equivalent) or switching to an in-process Whisper binding (a materially larger engineering change than the exposure justifies). The window is bounded by transcription time — typically seconds, not persistent — and is already defended in depth:

- Both scratch files are clamped to **owner-only `chmod 0600`** immediately after creation (`crate::perms::chmod_0600_unix`, called at `whisper.rs:141` for the audio and `whisper.rs:178` for the transcript).
- Both are wrapped in `Drop`-based RAII guards that unlink the file on **every exit path** — success, error, and panic alike — not just the happy path.
- Filenames use a random suffix (`getrandom`) so concurrent transcriptions cannot collide or have their cleanup clobbered.

### Conditions for this to remain an accepted risk

This item stays accepted **only** as long as all of the following remain true:

1. The `WavCleanup` and `TxtCleanup` RAII guards remain in place and are registered immediately after each file is created (before any operation that could return early).
2. Both scratch files continue to receive `chmod 0600` before any read occurs.
3. No new code path writes transcript or raw audio content to disk **without** an equivalent guaranteed-cleanup guard.
4. The CI log-PHI guardrail (`scripts/check_log_phi.sh`, added in `065b7ff`) continues to run and pass — it is the regression backstop that prevents the *content* of these scratch files from also leaking into the unencrypted OS-level app log via an incautious future `log::` call.

If whisper.cpp integration is ever rewritten (e.g., moved to an in-process binding, or a named-pipe approach), this item should be re-audited — the risk may shrink to zero, and this document should be updated accordingly rather than left stale.

---

## Item 3 — Audit-chain tail-truncation is not cryptographically detected (accepted)

### What it is

The `note_history` and `note_audit` audit chains are integrity-protected in two layers: a SHA-256 hash chain (each row commits to its payload and the prior row's hash) and a keyed HMAC per row (`audit_mac.rs`, keyed by an HKDF-derived value rooted in the SQLCipher DEK). Together these detect **substitution** and **edit** of any stored row. They do **not** detect **truncation** of the newest rows: a MAC-valid prefix of a chain is still MAC-valid, so an actor who drops the trailing entries leaves a chain that verifies clean.

### Why it is accepted, not fixed

An external "tip anchor" (a sidecar file recording each signed chain's expected tail) was prototyped to close this and then **removed as over-engineered for this deployment model**, for two reasons:

1. **The threat actor overlaps with the key holder.** Tahlk Solo is single-user and local-first; the only party who can make coherent writes to the *decrypted* database is the one holding the SQLCipher DEK. Any tip anchor keyed off that same DEK (the only key material on the device) can be re-forged by that same party. Cryptographic tamper-evidence against the record owner is not achievable on a local-first single-user app.
2. **At-rest file tampering is already covered.** SQLCipher authenticates every database page with an HMAC (`cipher_use_hmac` is on by default and is not disabled here), so raw-file tampering *without* the DEK is already detected on read, before any app-level check runs.

The tip anchor added ~300 LOC and a new file-corruption failure surface to close a corner that, on this deployment model, overlaps with the party it cannot stop. The SHA-256 hash chain plus the keyed HMAC are retained as proportionate, reasonable integrity mechanisms under §164.312(c)(1) ("a *reasonable and appropriate* mechanism to corroborate that ePHI has not been altered").

### Conditions under which this must be re-audited

This acceptance is specific to the single-user local-first model. Re-open it if any of these change:

1. **The product goes multi-user / multi-tenant** (e.g., the Firm tier becomes shared-record rather than bundled independent installs, or `tahlk-sync` / the frozen Group tier unfreezes). Then a tamperer need not be the record owner, and a truncation anchor keyed outside the DEK holder's control becomes meaningful.
2. **The encrypted database leaves the SQLCipher boundary** (cloud backup, sync, export of the raw DB) where an out-of-band actor could truncate a copy.
3. **`cipher_use_hmac` is ever disabled**, which would remove the at-rest page authentication this acceptance leans on.

---

## Pre-release compliance checklist

Run through this before every production release. Each item should be checked by a human, not assumed — this is the paper trail.

### Export disclosure (Item 1)

- [x] Export dialog / UI copy for `export_note_to_file` (.txt) states exported files are unencrypted and the provider's responsibility to secure — shipped `a607490`
- [x] Export dialog / UI copy for `export_note_pdf_to_file` (.pdf) states the same — shipped `a607490` (same disclosure line covers both buttons)
- [x] Diagnostics log export (`telemetry.js`'s `exportLog()`, which also routes through `export_note_to_file`) has its own disclosure — shipped `404bd82`. **Deliberately narrower copy, not a copy-paste of the note-export line**: verified the diagnostics log content is non-PHI by design (`scrubProps()`'s number/boolean/6-key allowlist; `recordError()`'s two PHI-adjacent call sites in `transcriber.js`/`noteGenerator.js` both flow through Rust `AppError` paths already redacted — `redact_whisper_stderr`, and `notes.rs`'s `UpstreamApi` which never carries the response body or request content), so the tooltip + helper text on "Export Log" in Settings state the *file* is unencrypted without implying it holds patient data — which would otherwise contradict the "No patient data...are ever recorded" copy one paragraph above it
- [x] Current HIPAA risk assessment / compliance documentation names unencrypted provider-directed export as a known, accepted data flow — shipped `docs/security/hipaa-risk-assessment.md` (Flow C)
- [x] No new export command was added since the last release without the same disclosure treatment (`grep -n "export_note\|fs::write" src-tauri/src/export.rs` — confirmed exactly the 2 known commands, no silent third path, as of `404bd82`)

### Transcript/audio scratch-file window (Item 2)

- [x] `WavCleanup` struct still exists in `whisper.rs` and is still registered immediately after the transient `.wav` is written (before the sidecar call) — re-verified `whisper.rs:134` (write) → `:137` (`WavCleanup` registered) → `:157` (sidecar `.output()` call). Confirmed as of this check.
- [x] `TxtCleanup` struct still exists in `whisper.rs` and is still registered immediately after the sidecar call returns (before checking `output.status`) — re-verified `whisper.rs:167` (`TxtCleanup` registered) precedes `:169` (`output.status` check), with an explicit `[audit M3]` comment justifying the ordering. Confirmed as of this check.
- [x] `chmod_0600_unix` is still called on both the transient `.wav` and the transcript `.txt` before either is read — re-verified `:141` (wav chmod, before any read) and `:178` (txt chmod, immediately before `:180`'s `read_to_string`, with an `[M1]` comment). Confirmed as of this check.
- [x] `cargo test --manifest-path src-tauri/Cargo.toml --locked` passes, specifically including `whisper::tests::wav_cleanup_removes_file_on_panic`, `whisper::tests::wav_cleanup_removes_file_on_drop`, `whisper::tests::txt_cleanup_removes_file_on_drop`, and `whisper::tests::txt_cleanup_ignores_missing_file` — re-ran all 4 individually (pass) and the full suite (134 passed, 1 failed — the known pre-existing sandbox-only `secrets::tests::keyring_roundtrip` D-Bus/X11 limitation, unrelated to app code, consistent across every phase of this project) as of this check.
- [x] `scripts/check_log_phi.sh` passes clean (run it directly: `bash scripts/check_log_phi.sh`) — this is also enforced by the `log-phi-guard` CI job, but confirm it locally before a release cut too — re-ran: clean pass (exit 0). Also re-verified the guardrail actually catches a real violation by injecting a canary `log::info!("transcript: {}", ...)` line (correctly failed, exit 1, flagged the exact line) then restored the file with a confirmed zero-diff. Confirmed as of this check.
- [x] No new call site writes raw audio or transcript content to disk without an equivalent RAII cleanup guard (spot-check: `grep -rn "tokio::fs::write\|std::fs::write" src-tauri/src/*.rs` against the known-accounted-for list from the last full audit) — re-ran: every production call site is accounted for (`audio.rs:83` and `audio_crypto.rs:227` write ciphertext only; `export.rs:36/68` are the two known disclosed export commands; `whisper.rs:134` is the guarded `.wav` scratch write); all other matches are inside `#[cfg(test)]` fixtures, not production paths. No new unaccounted-for site as of this check.
- [x] If the whisper.cpp integration architecture changed since the last release (e.g., in-process binding, named pipes), re-open this document and re-assess — do not just re-check the boxes above unchanged — confirmed via `git log 065b7ff..HEAD -- src-tauri/src/whisper.rs` returning zero commits: the file, and therefore the external-sidecar/file-based architecture (`app.shell().sidecar("whisper-cpp")`), is unchanged since the last audit. Re-audit not triggered.

### General

- [ ] This document's "As of commit" header is updated to the release commit hash
- [ ] Any newly accepted risk discovered since the last release is added to this document with the same structure (what it is / why accepted / conditions to remain accepted), not left as a verbal decision with no record
