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

`transcribe_audio` (`src-tauri/src/whisper.rs`) shells out to the bundled whisper.cpp sidecar, which is an external process that can only read/write real files on disk — it cannot accept in-memory buffers or piped bytes for this build. Because of that constraint there are **three** transient plaintext scratch artifacts, each guarded by the `TempFileCleanup` RAII struct (the single unified guard — it superseded the earlier separate `WavCleanup`/`TxtCleanup`/`ScratchFileCleanup` types) and enumerated by `whisper::SCRATCH_EXTS` = `[".wav", ".txt", ".json"]`:

- Session audio is decrypted to a transient plaintext `.wav` (`temp_wav`, guarded by `_wav_cleanup`).
- The sidecar's `--output-txt` transcript lands as a transient plaintext `.txt` (guarded by `_cleanup`).
- The sidecar's `--output-json-full` sidecar — token-level transcript detail — lands as a transient plaintext `.json` (guarded by `_json_cleanup`). It carries the same conversation text as the `.txt`, so it is exactly as sensitive.

All three are the actual patient-conversation content — the transcript files in particular are arguably the single most sensitive artifact anywhere in the pipeline, since they are the conversation in text form.

### Why this is accepted as residual risk, not fully eliminated

This is inherent to integrating a file-based external CLI tool; eliminating it entirely would require either a named-pipe/FIFO-based rewrite of the whisper integration (Unix-only, no reliable Windows/macOS equivalent) or switching to an in-process Whisper binding (a materially larger engineering change than the exposure justifies). On a **graceful** exit the window is bounded by transcription time — seconds — and is already defended in depth:

- All three scratch files are clamped to **owner-only `0600`** immediately after creation (the audio via `crate::perms::write_0600_unix`; the sidecar-written `.txt` and `.json` via `crate::perms::chmod_0600_unix` before either is read).
- All three are wrapped in `TempFileCleanup` `Drop`-based RAII guards that unlink the file on **every exit path** — success, error, and panic alike — not just the happy path.
- Filenames use a random suffix (`getrandom`) so concurrent transcriptions cannot collide or have their cleanup clobbered.

### Correction — the RAII guards do not cover an unclean shutdown (HITECH audit H-1)

This section previously read *"the window is bounded by transcription time — typically seconds, **not persistent**."* **That was wrong for the crash case, and the acceptance above rested on it.**

`Drop` does not run on `SIGKILL`, `taskkill /F`, an OOM kill, or a power cut. Anything left by one of those persists indefinitely: the decrypted `.wav`, the transcript `.txt`, and the `.json` (which carries the same transcript text). That is **unsecured PHI at rest** under §164.402, and its presence forfeits the breach-notification safe harbor for the whole device — the encrypted database stops mattering once a plaintext copy of the same conversation sits beside it. A device loss that would otherwise be exempt becomes notifiable under §164.404.

The prior `reconcile_orphaned_audio` sweep could not help: it only considers files ending `.wav.enc` and `continue`s past everything else by construction.

**Closed by** `audio::purge_transcription_scratch` — a startup sweep that removes all three artifact kinds, records one `destruction_log` row (`legal_basis = "unclean_shutdown"`) with the count, and logs a warning, since a non-zero result is itself evidence an incident review needs. It runs on **both** startup paths (`lib.rs::setup` for fresh installs, `auth_unlock_password` for auth-configured ones) and before the at-rest migration, so a scratch `.wav` can never be mistaken for legacy session audio.

Matching is deliberately tight — exact prefix, exactly 16 hex chars, known extension — because the sweep deletes unconditionally in the directory that also holds encrypted session audio. `whisper::is_scratch_artifact` owns the predicate next to the code that constructs the names, and two tests pin both directions.

**The residual risk that remains** is the in-flight window on a graceful run, which the original defenses (0600, RAII, random suffixes) still bound to seconds. The crash case is no longer accepted risk — it is closed.

### Conditions for this to remain an accepted risk

This item stays accepted **only** as long as all of the following remain true:

1. A `TempFileCleanup` RAII guard is registered for **each** of the three scratch artifacts (`.wav`, `.txt`, `.json`) immediately after the file is created (before any operation that could return early). If the sidecar is ever asked for a fourth output, it needs its own guard and a `SCRATCH_EXTS` entry in the same commit.
2. All three scratch files continue to receive `0600` before any read occurs.
3. No new code path writes transcript or raw audio content to disk **without** an equivalent guaranteed-cleanup guard.
4. The CI log-PHI guardrail (`scripts/check_log_phi.sh`, added in `065b7ff`) continues to run and pass — it is the regression backstop that prevents the *content* of these scratch files from also leaking into the unencrypted OS-level app log via an incautious future `log::` call.
5. `audio::purge_transcription_scratch` still runs on **both** startup paths, and `whisper::is_scratch_artifact` still recognizes every name `transcribe_audio` constructs. If the scratch naming or the sidecar's output extensions change, the predicate and its tests must change in the same commit — otherwise the sweep silently stops finding the files it exists to remove, and this item reverts to an open gap rather than an accepted risk.

If whisper.cpp integration is ever rewritten (e.g., moved to an in-process binding, or a named-pipe approach), this item should be re-audited — the risk may shrink to zero, and this document should be updated accordingly rather than left stale.

---

## Item 2b — The pre-auth window is now closed for PHI creation (HITECH audit M-3)

Before `auth_set_password` runs, the DEK lives in the OS keychain in plaintext
and `lib.rs::setup` opens the database with it. PHI written in that window is
encrypted under a key sitting on the same device, unlocked by the OS login.
HHS conditions the §164.402 safe harbor on the decryption key not having been
breached, so this was the one place in the app where the safe harbor rested on
the OS keychain alone.

The app already avoided it — `entry-solo.js` forces first-open password setup
before the UI is usable — but that gate lived in the **renderer**, on the
untrusted side of the boundary this codebase defends everywhere else.

`auth::require_auth_configured` now enforces the same rule server-side on the
three PHI-creating commands: `upsert_patient`, `upsert_encounter`,
`save_session_audio`.

**Deliberately gates creation, not access.** Reads stay open, and so do
deletes. A provider mid-migration — data from before auth existed, password not
yet set — must not be locked out of their own records, and blocking reads would
strand them. Deleting PHI before setup is not a confidentiality risk, so it is
out of scope for this control.

Nothing legitimate writes PHI before setup: onboarding writes only the provider
profile and the BAA ack, both settings, neither gated.

**Residual:** an install that already holds PHI created before this shipped is
unaffected — the guard prevents new writes, it cannot retroactively re-key old
ones. Those records are re-protected the moment the provider sets a password,
which the app forces on next launch.

---

## Item 3 — Audit-chain tail-truncation is not cryptographically detected (accepted)

### What it is

The `note_history` and `note_audit` audit chains are integrity-protected in two layers: a SHA-256 hash chain (each row commits to its payload and the prior row's hash) and a keyed HMAC per row (`audit_mac.rs`, keyed by an HKDF-derived value rooted in the SQLCipher DEK). Together these detect **substitution** and **edit** of any stored row. They do **not** detect **truncation** of the newest rows: a MAC-valid prefix of a chain is still MAC-valid, so an actor who drops the trailing entries leaves a chain that verifies clean.

### Update — a bypass that was never accepted, and an acceptance that was too broad

An external architecture audit's tampering cases were re-executed against this
codebase rather than reasoned about. Two findings resulted.

**First, a bypass nobody had accepted.** Both `verifyAuditChain` and
`verifyHistoryChain` carried a "legacy" exemption skipping an entry that lacked
`entryHash` before the chain started. Stripping the field from *every* entry
meant the chain never started, every row was skipped, and the whole log
verified clean. Deleting the integrity metadata was a way to satisfy the
integrity check — no key, no forgery, no cryptography. Both hatches are now
removed; a missing `entryHash` is a broken chain wherever it appears. Pinned by
`tests/js/test_auditChain_tampering.mjs`.

**Second, this acceptance conflated two threats.** The reasoning below — that
the tamperer and the key-holder are the same party on a single-user local-first
app — is sound for *deliberate* tampering. It does not cover **accidental
loss**: a partial write, a failed restore, a truncated backup, a sync that
dropped rows. There nobody is attacking anything, and a short or emptied
history simply read as clean, because the chain has no idea how long it is
supposed to be.

`verifyAuditChain` now accepts `{ expectedCount, expectedHead }` and fails when
either disagrees with the log. **Remaining work: persist that anchor on the
encounter row and pass it at every call site.** Until that lands, truncation
detection is available but not enforced end to end, and the acceptance below
still governs in practice.

What genuinely remains accepted is forgery by an actor holding the DEK.
`entryHash` is an unkeyed SHA-256 over public fields, so key access permits
recomputing the chain; `audit_mac.rs` raises the bar to "needs the key" but
cannot go further on a device where the key lives.

### Why it is accepted, not fixed

An external "tip anchor" (a sidecar file recording each signed chain's expected tail) was prototyped to close this and then **removed as over-engineered for this deployment model**, for two reasons:

1. **The threat actor overlaps with the key holder.** Tahlk Solo is single-user and local-first; the only party who can make coherent writes to the *decrypted* database is the one holding the SQLCipher DEK. Any tip anchor keyed off that same DEK (the only key material on the device) can be re-forged by that same party. Cryptographic tamper-evidence against the record owner is not achievable on a local-first single-user app.
2. **At-rest file tampering is already covered.** SQLCipher authenticates every database page with an HMAC (`cipher_use_hmac` is on by default and is not disabled here), so raw-file tampering *without* the DEK is already detected on read, before any app-level check runs.

> **Whole-DB rollback is now *detected* (finding #2/C4).** Truncation of the *current* chain by the DEK holder stays accepted as above, but the distinct attack of swapping the entire `tahlk.db` for an older captured snapshot is caught: a random generation token is stamped into both the encrypted main DB and the plaintext wraps DB on each legitimate new generation (create / migration / restore), and a mismatch on open records a durable `rollback_suspected` auth-audit event. The check is fail-**open** (records, never blocks) and does not defeat the DEK holder — but a filesystem-only attacker cannot rewrite the token inside the encrypted main DB to match, so their older snapshot is flagged. See `db.rs::reconcile_db_generation`.

The tip anchor added ~300 LOC and a new file-corruption failure surface to close a corner that, on this deployment model, overlaps with the party it cannot stop. The SHA-256 hash chain plus the keyed HMAC are retained as proportionate, reasonable integrity mechanisms under §164.312(c)(1) ("a *reasonable and appropriate* mechanism to corroborate that ePHI has not been altered").

### Conditions under which this must be re-audited

This acceptance is specific to the single-user local-first model. Re-open it if any of these change:

1. **The product goes multi-user / multi-tenant** (e.g., the Firm tier becomes shared-record rather than bundled independent installs, or `tahlk-sync` / the frozen Group tier unfreezes). Then a tamperer need not be the record owner, and a truncation anchor keyed outside the DEK holder's control becomes meaningful.
2. **The encrypted database leaves the SQLCipher boundary** (cloud backup, sync, export of the raw DB) where an out-of-band actor could truncate a copy.
3. **`cipher_use_hmac` is ever disabled**, which would remove the at-rest page authentication this acceptance leans on.

---

## Item 4 — `destruction_log`, `config_audit`, `auth_audit` are append-only but not keyed-HMAC-chained (accepted)

### What it is

Three audit tables — `destruction_log` (PHI disposal), `config_audit` (retention / hold / lock / restore settings), and `auth_audit` (authentication events) — record legally consequential activity but, unlike `note_history` / `note_audit`, carry **no per-row hash or keyed MAC**. Their integrity rests on the fact that **no delete or update command is exposed** for them via the Tauri IPC surface (verified against the full `invoke_handler` list): a compromised WebView can append and read, never erase or edit.

### Why it is accepted, not fixed

1. **Same DEK-holder overlap as Item 3.** `config_audit` and `destruction_log` live inside the SQLCipher database. The only party who can make coherent edits to the *decrypted* rows is the DEK holder, and an app-level MAC rooted in that same DEK can be re-forged by that same party — so a keyed chain buys nothing against the one actor who could bypass the append-only IPC surface. This is exactly the reasoning in Item 3.
2. **`auth_audit` cannot be DEK-keyed even in principle.** Its rows are written during *failed* unlock attempts — **before any DEK or MAC key exists** (that is the whole reason it lives in the always-openable plaintext `tahlk_auth.db` rather than the encrypted DB). A MAC key derived from the DEK cannot cover rows written when the DEK is unavailable. It is deliberately **metadata-only** (timestamp, event, outcome — no PHI, no identity) precisely so that leaving it unencrypted and un-MAC'd discloses nothing sensitive.
3. **At-rest page tampering of the two encrypted tables is already caught** by SQLCipher's per-page HMAC (`cipher_use_hmac` on), as in Item 3.

### Conditions under which this must be re-audited

1. Any of Item 3's conditions (multi-user / multi-tenant; the encrypted DB leaving the SQLCipher boundary).
2. **Any delete or update command is ever exposed** for these tables — the append-only-IPC property is the entire control here.
3. **`auth_audit` ever gains a field beyond bounded metadata** (e.g. an actor identity or free-text detail), at which point its plaintext, un-authenticated storage would need to be reconsidered.

---

## Item 5 — Sign-off content hash is client-computed, not independently re-derived server-side (accepted, tracked)

### What it is

`computeNoteHash` (`src/utils/contentHash.js`) runs in the WebView and the resulting `signed_hash` is passed to Rust, which stores it **without independently recomputing** it from the note content in the KV store (`note_content_v1::<id>`). So the hash attests to *what the client said the content was*, not to what is actually stored.

### Why it is accepted (and narrower than it looks)

Post-sign content is **immutable server-side** (`kv.rs::block_if_encounter_signed` rejects any write to a signed encounter's content), so the primary tamper vector — editing the note after signing — is already blocked regardless of the hash. The residual is confined to a bug, race, or compromised WebView persisting a `signed_hash` that never matched the text *at sign time*; the keyed-MAC chain then faithfully protects that (possibly-wrong-at-birth) hash from later alteration.

### Why it is not yet fixed in code

Deriving the hash server-side requires Rust to reproduce the JS JSON canonicalization **byte-for-byte** (fixed key order, `JSON.stringify`-compatible string escaping). A mismatch would reject *legitimate* sign-offs, so this must be developed and validated against a running build rather than shipped from a static edit. Tracked as a follow-up; when implemented, Rust should **derive** the hash server-side (from the KV content it can already read) rather than trust a client-supplied value.

---

## Pre-release compliance checklist

Run through this before every production release. Each item should be checked by a human, not assumed — this is the paper trail.

### Export disclosure (Item 1)

- [x] Export dialog / UI copy for `export_note_to_file` (.txt) states exported files are unencrypted and the provider's responsibility to secure — shipped `a607490`
- [x] Export dialog / UI copy for `export_note_pdf_to_file` (.pdf) states the same — shipped `a607490` (same disclosure line covers both buttons)
- [x] Diagnostics log export (`telemetry.js`'s `exportLog()`, which also routes through `export_note_to_file`) has its own disclosure — shipped `404bd82`. **Deliberately narrower copy, not a copy-paste of the note-export line**: verified the diagnostics log content is non-PHI by design (`scrubProps()`'s number/boolean/6-key allowlist; `recordError()` persists only `kind`/`name`/`code` and drops the raw `error.message` entirely, with any string `code` gated on the `SAFE_ERROR_CODE` short-token shape — shipped L4 in `4a9ea6e` (#43)), so the tooltip + helper text on "Export Log" in Settings state the *file* is unencrypted without implying it holds patient data — which would otherwise contradict the "No patient data...are ever recorded" copy one paragraph above it
- [x] Current HIPAA risk assessment / compliance documentation names unencrypted provider-directed export as a known, accepted data flow — shipped `docs/security/hipaa-risk-assessment.md` (Flow C)
- [x] No new export command was added since the last release without the same disclosure treatment (`grep -n "export_note\|fs::write" src-tauri/src/export.rs` — confirmed exactly the 2 known commands, no silent third path, as of `404bd82`)

### Transcript/audio scratch-file window (Item 2)

- [ ] The unified `TempFileCleanup` guard is registered for **all three** scratch artifacts, each immediately after its file exists: `_wav_cleanup` right after the decrypted `.wav` is written (before the sidecar call), and `_cleanup` (`.txt`) + `_json_cleanup` (`.json`) right after the sidecar returns (before the `output.status` check, since the sidecar can write partial output on a non-zero exit). Verify by reading the three registration sites, not the line numbers — the old separate `WavCleanup`/`TxtCleanup`/`ScratchFileCleanup` structs were unified into `TempFileCleanup`, so a check keyed to the old names would silently pass against absent code.
- [ ] `0600` is applied to **all three** before any read — the `.wav` via `write_0600_unix` at creation; the sidecar-written `.txt` and `.json` via `chmod_0600_unix` before `read_to_string`.
- [ ] `cargo test --manifest-path src-tauri/Cargo.toml --locked` passes, specifically including the `TempFileCleanup` RAII tests — `whisper::tests::wav_cleanup_removes_file_on_drop`, `whisper::tests::wav_cleanup_removes_file_on_panic`, `whisper::tests::wav_cleanup_ignores_missing_file`, `whisper::tests::scratch_file_cleanup_removes_file_on_drop`, `whisper::tests::scratch_file_cleanup_ignores_missing_file` — plus the sweep-predicate tests `whisper::tests::scratch_names_match_the_sweep_predicate` and `whisper::tests::session_audio_and_near_misses_are_not_scratch` (the `txt_cleanup_*` tests named in a prior revision were renamed when the guards were unified).
- [x] `scripts/check_log_phi.sh` passes clean (run it directly: `bash scripts/check_log_phi.sh`) — this is also enforced by the `log-phi-guard` CI job, but confirm it locally before a release cut too — re-ran: clean pass (exit 0). Also re-verified the guardrail actually catches a real violation by injecting a canary `log::info!("transcript: {}", ...)` line (correctly failed, exit 1, flagged the exact line) then restored the file with a confirmed zero-diff. Confirmed as of this check.
- [x] No new call site writes raw audio or transcript content to disk without an equivalent RAII cleanup guard (spot-check: `grep -rn "tokio::fs::write\|std::fs::write" src-tauri/src/*.rs` against the known-accounted-for list from the last full audit) — re-ran: every production call site is accounted for (`audio.rs`/`audio_crypto.rs` write ciphertext only; `export.rs` holds the two known disclosed export commands; the guarded `.wav` scratch write in `whisper.rs` is the only raw-audio `fs::write`). The sidecar-written `.txt`/`.json` are NOT `fs::write` call sites — whisper-cpp writes them — so they are covered by the guard/predicate checks above and the `SCRATCH_EXTS`/`is_scratch_artifact` pairing rather than by this `fs::write` grep. All other `fs::write` matches are inside `#[cfg(test)]` fixtures, not production paths.
- [ ] `audio::purge_transcription_scratch` is still called from BOTH `lib.rs::setup` and `auth::auth_unlock_password`, and still runs BEFORE `migrate_plaintext_audio_at_rest` on each — verify by reading both call sites, not by trusting this box. The sweep is what keeps the §164.402 safe harbor across a crash; a silently-dropped call site restores the gap with no test failure, since the unit tests exercise the function directly rather than its wiring.
- [ ] `whisper::is_scratch_artifact` still matches every extension the sidecar emits — currently `.wav` (ours), `.txt` and `.json` (from `--output-txt` / `--output-json-full`). If a whisper.cpp upgrade adds an output format, add its extension and a test in the same commit.
- [x] If the whisper.cpp integration architecture changed since the last release (e.g., in-process binding, named pipes), re-open this document and re-assess — do not just re-check the boxes above unchanged — confirmed via `git log 065b7ff..HEAD -- src-tauri/src/whisper.rs` returning zero commits: the file, and therefore the external-sidecar/file-based architecture (`app.shell().sidecar("whisper-cpp")`), is unchanged since the last audit. Re-audit not triggered.

### General

- [ ] This document's "As of commit" header is updated to the release commit hash
- [ ] Any newly accepted risk discovered since the last release is added to this document with the same structure (what it is / why accepted / conditions to remain accepted), not left as a verbal decision with no record
