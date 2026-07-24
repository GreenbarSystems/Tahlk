# Tahlk Solo — HIPAA Security Risk Assessment

**Status:** Active compliance record
**Scope:** Solo tier desktop application only (`src/group/` and `server/` —
the `tahlk-sync` Group-tier backend — are explicitly out of scope; that
service is frozen per [ADR 0001](../adr/0001-freeze-group-tier-and-sync.md)
and has zero validated demand or production deployment as of this writing).
**As of commit:** `5885922` (idle-lock setting audit, M2)
**Prior source material this assessment consolidates:**
- `tahlk-security-audit.md` — the original numbered finding set (C1–C2, H1–H6,
  M1–M10, L1–L5), referenced throughout the codebase (e.g. `notes.rs:334,336`,
  `whisper.rs` M1/M3 comments) and in
  [`docs/security/pre-deploy-checklist.md`](./pre-deploy-checklist.md). That
  file is not present in this checkout; this assessment does not restate its
  full contents, only the parts independently re-verified below.
- [`AUDIT-RESIDUAL-RISK.md`](../../AUDIT-RESIDUAL-RISK.md) — the two accepted
  residual risks (note export, transcript scratch-file window) and their
  disclosure/mitigation conditions.
- Direct code verification performed in this assessment pass (see citations
  inline — every claim below was checked against the current `main` branch,
  not assumed from prior reports).

This document exists to satisfy `AUDIT-RESIDUAL-RISK.md` Item 1's compliance
documentation condition: *"Tahlk's HIPAA risk assessment / Business Associate
context documentation must name this exact behavior (unencrypted,
provider-directed export) as a known, accepted data flow — not omit it."*
That requirement is met in [§2, Flow C](#flow-c--provider-directed-note-pdftxt-export-unencrypted).
It also documents the other PHI data flows so this is a real risk assessment,
not a single-purpose patch.

---

## 1. Where PHI lives and moves in Tahlk Solo

Tahlk Solo is a single-user, local-first desktop app (Tauri + Rust backend,
JS/HTML frontend). There is no Tahlk-operated backend in Solo mode — every
data flow below is either fully on-device or a direct device-to-third-party
call the provider explicitly triggers.

| # | Flow | PHI involved | At rest / in transit | Encrypted? |
|---|------|--------------|----------------------|------------|
| A | Session audio recording | Patient conversation audio | At rest (device) | Yes — AES-256-GCM (`0e32611`) |
| B | Transcription (whisper.cpp sidecar) | Patient conversation, audio + text | Transient at rest (device) | No — bounded-window plaintext, see [§2 Flow B](#flow-b--transcript-and-audio-scratch-files-transient-plaintext) |
| C | Note export (.txt / .pdf) | Full clinical note | At rest (device, provider-chosen path) | No — by design, see [§2 Flow C](#flow-c--provider-directed-note-pdftxt-export-unencrypted) |
| D | Note generation (Anthropic; managed-key proxy) | Patient conversation transcript | In transit (network) | Yes (TLS) in transit; **managed-key proxy shipped (ADR 0006) and BAA gate enforced, but the executed-contract prerequisites are still pending: Greenbar↔Anthropic BAA executed 2026-07-18 with ZDR provisioning pending Anthropic approval; provider↔Greenbar BAA + EULA not yet executed with any practice. Real-PHI use is gated procedurally until both land** — see [§2 Flow D](#flow-d--note-generation-via-anthropic-managed-key-proxy) |
| E | Signed note, transcript, audit log, provider/patient records | Everything above, persisted | At rest (device, app-managed SQLite) | Yes — SQLCipher (confirmed clean in the prior PHI-at-rest audit) |
| F | Diagnostics log export | App diagnostics only | At rest (device, provider-chosen path) | No, but confirmed non-PHI, see [§2 Flow F](#flow-f--diagnostics-log-export-unencrypted-file-no-phi-content) |

Flows A and E are fully mitigated (encrypted at rest) and are not treated as
residual risk. Flows B, C, D, and F are addressed individually below because
each has a different risk shape and a different reason it's accepted rather
than blocked outright.

The data-flow table above covers *where PHI moves*. It does not cover *who
can reach it* or *how activity involving it is tracked* — those are separate
Security Rule standards (Access Control, §164.312(a); Audit Controls,
§164.312(b)) with their own required implementation specifications. Sections
3 and 4 below document those specifications directly, since a July 2026
internal compliance audit (`tahlk_compliance_audit.md`) found this document
did not previously address them at all. Sections 5–7 similarly cover
contingency planning, breach notification, and retention/disposal — three
more areas that audit found entirely undocumented.

---

## 2. Data flow detail

### Flow B — Transcript and audio scratch files (transient plaintext)

**What it is.** `transcribe_audio` (`src-tauri/src/whisper.rs`) shells out to
the bundled whisper.cpp sidecar binary, which can only read/write real files
on disk — not in-memory buffers. So session audio is decrypted to a
transient plaintext `.wav`, and the sidecar's output lands as a transient
plaintext `.txt`. Both are the actual patient-conversation content.

**Risk classification:** Accepted residual risk (not eliminated in code).

**Mitigations in place (independently re-verified this pass):**
- Both scratch files are clamped to owner-only `chmod 0600` immediately after
  creation, before any read (`whisper.rs:141` for audio, `whisper.rs:178` for
  transcript, the latter directly preceding `read_to_string` at `:180`).
- Both are wrapped in `Drop`-based RAII guards (`WavCleanup`, `TxtCleanup`)
  registered immediately after each file is created/produced — `WavCleanup`
  at `:137` (before the sidecar call at `:157`), `TxtCleanup` at `:167`
  (before the `output.status` check at `:169`, deliberately, since the
  sidecar can write the `.txt` even on a non-zero exit) — so every exit path,
  including panics, unlinks the file.
- Filenames use a random suffix so concurrent transcriptions can't collide.
- A CI static-analysis guardrail (`scripts/check_log_phi.sh`, added `065b7ff`)
  blocks any `log::` call site that references PHI-named tokens
  (`transcript|note|content|patient|provider_name|chief_complaint`), so this
  scratch content can't leak into the unencrypted OS-level app log via a
  future careless log line. Verified this pass: passes clean, and correctly
  fails when a live violation is injected (tested via canary injection +
  restore with zero diff).

**Why accepted, not fully eliminated:** removing this would require either a
named-pipe/FIFO rewrite (Unix-only, no reliable cross-platform equivalent) or
switching to an in-process Whisper binding — materially larger engineering
effort than the exposure justifies given the window is bounded by
transcription time (seconds) and already defended in depth as above.

**Conditions to remain accepted** (re-verify every release; see
`AUDIT-RESIDUAL-RISK.md` Item 2 checklist): guards still registered in the
correct order, `chmod 0600` still precedes any read, log-PHI guardrail still
passes, no new unguarded write path introduced, and the whisper.cpp
integration architecture hasn't changed (would trigger re-audit).

---

### Flow C — Provider-directed note PDF/TXT export (unencrypted)

**What it is.** `export_note_to_file` and `export_note_pdf_to_file`
(`src-tauri/src/export.rs`) write full clinical note content — unencrypted —
to a location the provider explicitly chooses via the OS's native Save-As
dialog. This is the exact behavior this document is required to name as a
known, accepted data flow per `AUDIT-RESIDUAL-RISK.md` Item 1.

**Risk classification:** Accepted residual risk — user-directed data flow,
working as designed, not a code defect.

**Why this is accepted rather than remediated in code:** HIPAA's at-rest
encryption requirement (§164.312(a)(2)(iv)) governs data the *application* is
responsible for storing. Once a provider deliberately exports a note to their
own filesystem — the same action as printing a note or exporting a PDF from
any EHR — responsibility for that copy's security transfers to the provider's
own endpoint security posture (full-disk encryption, workstation policy,
physical security). Tahlk cannot control the file once it leaves the app's
managed, encrypted storage.

**Mitigations in place:**
- The export flow is user-initiated only — never a background or silent
  write. The provider must actively click Export and choose a destination
  every time.
- In-product disclosure (`a607490`): persistent helper text under the export
  controls in both the draft and signed-note states, plus a matching hover
  tooltip on the Save File / Save as PDF buttons, stating exported files are
  not encrypted by Tahlk and the provider is responsible for securing the
  file once it leaves the app. Shown on every render — not a one-time
  dismissible modal — because the risk applies to every export, not just the
  first.
- Compliance documentation naming this behavior: **this document** (closes
  the second, previously-open condition from `AUDIT-RESIDUAL-RISK.md` Item 1).

**Conditions to remain accepted:** the in-product disclosure must remain
visible on both export buttons; this document must continue to name the
behavior; no new export command may be added without the same disclosure
treatment (checked via `grep -n "export_note|fs::write" src-tauri/src/export.rs`
— confirmed exactly 2 commands, no third path, as of `404bd82`).

---

### Flow D — Note generation via Anthropic (managed-key proxy)

**What it is.** `generate_note` (`src-tauri/src/notes.rs`) sends the session
transcript — PHI — to Anthropic's API to produce the structured clinical note.

The **governing model is managed-key** (see `MANAGED-KEY-ROLLOUT.md`): **Greenbar
Systems is the provider's Business Associate**, and Greenbar — not the individual
practice — holds the relationship with Anthropic, which is Greenbar's
**subcontractor**. The provider's agreements are with Greenbar: a Business
Associate Agreement (BAA) and an End User License Agreement (EULA).

**Current implementation, stated plainly to avoid overclaiming in either
direction:** the managed-key proxy is now **built and shipped** ([ADR 0006](../adr/0006-enforce-baa-gate-managed-key.md),
2026-07-23). BYOK is **fully retired** — the desktop app holds no Anthropic key
of its own and routes every `generate_note` call through Greenbar's server-side
proxy, which uses Greenbar's own key (`notes.rs`, `device.rs`,
`MANAGED-KEY-ROLLOUT.md`). The BAA acknowledgment gate is **enforced in
production** (`baa::GATE_ENABLED = true`), and onboarding now blocks on the
BAA/EULA acknowledgment. **The code has caught up to the compliance model; the
executed contracts have not** (see status below).

**Risk classification:** Conditionally permitted third-party PHI disclosure —
gated, not blanket-accepted. **The unmet condition has moved from code to
paper.** The technical prerequisites are in place — proxy live, gate enforced,
BYOK gone — so nothing in the software now restricts transmission to test data
the way the ADR-0003 beta (gate disabled, test-data-only) did. What is *not* yet
in place is the executed BAA chain and ZDR provisioning. This is the material
open item, and it cuts the opposite way from before:

> **The test-data-only guardrail is now PROCEDURAL, not technical.** Under
> ADR 0003 the gate was disabled and the arrangement was BYOK-beta; real PHI
> simply wasn't wired to flow. Under ADR 0006 it is: a provider who completes
> onboarding and checks the acknowledgment box **will** transmit real
> transcripts through the managed proxy. The in-app acknowledgment is a local
> flag, **not** evidence that the legal BAA + EULA are executed or that ZDR is
> active upstream. Until the contracts below are executed, the only thing
> keeping real PHI out of an unbacked disclosure chain is the operational
> decision not to invite real-PHI practices — hold that line, and do not read
> the enforced gate as if it were that safeguard.

**Why sending PHI to Anthropic is not an automatic compliance violation:**
HIPAA permits a Covered Entity to disclose PHI to a Business Associate under a
signed BAA, and permits that Business Associate to use a subcontractor under a
back-to-back BAA. The intended chain is: **provider (Covered Entity) → Greenbar
(Business Associate, under the provider↔Greenbar BAA) → Anthropic
(subcontractor, under Greenbar's BAA with Anthropic)**. Every link needs a BAA;
the ones still pending are called out below. Tahlk's in-app mitigation is a hard
technical gate, not a policy statement:

- `require_ack` (`src-tauri/src/baa.rs`) is called at the very top of
  `generate_note` — strictly before the API key is read, before the HTTP client
  is built, and before the transcript is touched in any way. If the provider has
  not confirmed the required agreements, the call is refused with
  `AppError::BaaRequired` and **no transcript content leaves the device.** This
  ordering is deliberate and documented inline in the source.
- The transcript is TLS-encrypted in transit to Anthropic (standard HTTPS).
- Prompt-injection hardening wraps the transcript in tagged delimiters before
  it's sent (audit finding H6).
- Upstream error handling never surfaces the request or response body into
  logs or the app's error surface — only an HTTP status code or a fixed
  generic string (audit findings M9/M10) — so a failed generation call can't
  leak transcript content through the error path.

**Current real-world status (self-reported by the product owner; code cannot
confirm the state of a legal agreement):**

- **Greenbar ↔ Anthropic BAA:** **executed 2026-07-18.** Zero-Data-Retention
  (ZDR) provisioning on the dedicated Anthropic organization behind the
  now-shipped managed-key proxy is **still pending Anthropic approval** — the BAA
  is signed, but ZDR must be provisioned on the org before the
  `TAHLK_ANTHROPIC_KEY` in `MANAGED-KEY-PROXY-CONTRACT.md` §3 is usable for
  real-PHI traffic (see that contract's §3 and §7, which require the upstream
  Anthropic org to have ZDR enabled). **This is now the binding constraint:** the
  proxy code is deployed and the gate is enforced, so ZDR provisioning — not the
  proxy build — is what stands between the current state and compliant real-PHI
  traffic. Update this line — with the Anthropic-provided approval date — the
  moment ZDR is confirmed active on the org; do not treat the signed BAA alone,
  or the shipped proxy, as sufficient to route real PHI.
- **Provider ↔ Greenbar BAA + EULA:** **in attorney drafting, week of
  2026-07-13.** A licensed healthcare attorney is drafting both agreements —
  see the required-contract-elements list in `MANAGED-KEY-ROLLOUT.md` §2
  ("BAA template ready to sign with each practice"). Not yet executed with any
  practice. Neither agreement is available to show a practice until the
  attorney-reviewed drafts land; real-PHI beta invitations must not go out
  before that point.

**Action items (not code concerns):** Tahlk's technical gate only enforces that
*some* confirmation exists in the local database — it does not itself constitute
or replace the signed agreements. **Item (3) — build the managed-key proxy — is
now done** (ADR 0006); the remaining items are contractual/operational and are
what now gate real-PHI use: (1) confirm ZDR provisioning on the Anthropic org
and record the approval date on the status line above; (2) finalize the
attorney-drafted provider↔Greenbar BAA and EULA, then execute them with each
practice before that practice uses real patient information; (3) **do not send
real-PHI beta invitations until (1) and (2) are complete** — with the gate now
enforced and BYOK gone, this is the only remaining barrier and it is procedural,
so it must be held deliberately; (4) keep the in-app confirmation
(`baa_ack_set`) in sync with those real-world agreements — the gate trusts the
local flag; it cannot verify the underlying paperwork.

**Conditions to remain accepted:** `require_ack` must remain the first statement
in `generate_note` (before any key read, client build, or transcript handling);
the confirmation flow must remain a hard `Result` gate (`AppError::BaaRequired`),
not a soft warning; and the managed-key proxy — now shipped and re-assessed
under this document per ADR 0006 — moves the Anthropic API key server-side to
Greenbar (per `MANAGED-KEY-PROXY-CONTRACT.md` §1's own banner: *"The proxy is a
HIPAA Business Associate... MUST NOT log, persist, or cache request/response
bodies."*), so the proxy's own no-retention behavior must be verified as an
operational control, not assumed from the contract text.

---

### Flow F — Diagnostics log export (unencrypted file, no PHI content)

**What it is.** Settings → Diagnostics → "Export Log" also calls
`export_note_to_file`, so mechanically it writes an unencrypted file — the
same command Flow C uses. The content, however, is a different case.

**Risk classification:** Low — content confirmed non-PHI; disclosure is about
the file mechanism only, not data sensitivity.

**Why this doesn't need the same disclosure strength as Flow C:** traced
every path that can put data into this log:
- `telemetry.track()`'s `scrubProps()` (`src/core/telemetry.js`) allows only
  numbers, booleans, and 6 hardcoded non-PHI string keys (`code`, `kind`,
  `template`, `status`, `os`, `appVersion`) — everything else is dropped, not
  truncated-and-kept.
- `telemetry.recordError()`, the one path that stores a raw (200-char
  truncated) message, has its two PHI-adjacent call sites
  (`transcriber.js`, `noteGenerator.js`) both routed through Rust error
  variants already hardened to exclude transcript/response content:
  `AppError::Transcription` only ever carries `redact_whisper_stderr`'s
  output, and `AppError::UpstreamApi`/`Internal` are built only from an HTTP
  status code or a fixed generic string — never the request or response
  body (audit M9/M10, `notes.rs:408-422`).

**Mitigation in place:** narrower disclosure copy (`404bd82`) on the Export
Log button and as persistent helper text — states the exported *file* is
unencrypted without implying it holds patient data, since the adjacent
Settings copy already (accurately) states no patient data, transcripts,
notes, or audio are ever recorded in this log.

---

## 3. Access control and person/entity authentication (§164.312(a), (d))

**Status: substantially remediated in code (see revision history).** When
these subsections were first written (`c9007ad`) all three were open gaps and
the app relied entirely on external OS-level controls. Since then the
first-open authentication design ([ADR 0004](../adr/0004-first-open-authentication.md))
and the idle auto-logoff have both **shipped and are enforced in production**,
so the subsections below now describe *implemented* controls, with the specific
residuals (biometric unlock not built; per-entry audit-actor attribution)
named explicitly rather than the whole control being deferred. Each required
implementation specification is addressed by real code; the earlier "planned,
not yet built" framing is retained only in the revision history as a record of
what changed.

### 3.1 Person or entity authentication — §164.312(d) (required)

**Current state: implemented (ADR 0004).** Tahlk now has an application-layer
authentication gate that runs **before the app shell renders** at every launch
(`src/entry-solo.js` `bootstrap()` blocks on `showSignInScreen()` when auth is
configured, and forces `runFirstOpenAuth()` on a fresh install). The control is
cryptographic, not cosmetic:

- The clinician sets a **master password** at first open (minimum 12 characters,
  checked against a bundled list of the 10,000 most common passwords), hashed
  with PBKDF2-HMAC-SHA256 at 210,000 iterations (`src-tauri/src/auth.rs`).
- The SQLCipher DEK is no longer stored plaintext in the keychain. It is
  **wrapped** (AES-256-GCM) under a password-derived KEK in a separate
  `tahlk_auth.db`, and `db_key.rs`'s `load_or_generate_dek()` **deletes** the
  plaintext keychain DEK once auth is configured and refuses to regenerate it —
  so the database can only be opened by someone who supplies the password (or a
  recovery code). This materially closes the "device theft plus keychain export"
  residual the `db_key.rs` module doc previously named.
- Three one-time **recovery codes** (Crockford base32 + checksum) provide account
  recovery without any Greenbar-side escrow.
- Authentication events (unlock success/failure, password change/reset,
  recovery-code use, the irreversible nuke) are recorded in a durable
  `auth_audit` trail — see §4.

**Residual (named, not deferred):** the **biometric unlock** option described in
ADR 0004 (Touch ID / Windows Hello, "Screen B") is **not implemented** — password
+ recovery codes only, on every platform. This is the conservative direction
(one fewer copy of the DEK) and is a UX gap, not a control gap. ADR 0004 should
read as "Accepted — partial" accordingly.

**Retained operational recommendation:** OS-level login + full-disk encryption
(FileVault/BitLocker) remain recommended complementary controls, but Tahlk no
longer *depends* on the OS session as its person-authentication boundary — the
in-app gate above is the primary control and is verifiable by Tahlk.

### 3.2 Unique user identification — §164.312(a)(2)(i) (required)

**Current state:** `src/core/capabilities.js`'s Solo-tier default is
`currentUser: () => null`. `src/core/auditLog.js`'s `actor` field falls back
to the hardcoded literal string `'provider'` whenever no user object exists
— which, in Solo mode today, is always. Every audit-log entry produced by
any installation is attributed to that same static string.

**Partially closed (ADR 0004 + server-derived actor).** Two things changed
since this was written:

- This install now has a **device-local authenticated identity** — the ADR 0004
  master password establishes that the person opening the app is the
  account-holder before any PHI is reachable (§3.1).
- The **Rust-side compliance trails** (`note_audit`, `patient_audit`,
  `destruction_log`, `config_audit`) already stamp a **server-derived provider
  name**, read from the onboarding provider profile via
  `kv_ops::provider_id(&conn)` — not a static placeholder. A compromised WebView
  cannot supply the actor for these rows; it is derived inside the Rust command.

**Residual (named, not deferred):** the **JS-side** audit log
(`src/core/auditLog.js`) still reads `currentUser()`, which
`src/core/capabilities.js` defaults to `null` in Solo tier, so its six action
types fall back to the literal `'provider'` string. Wiring `currentUser()` to
the provider-profile record (so the JS trail matches the Rust trails' real
attribution) remains the open item here. **Operational assumption meanwhile:**
Solo installations are single-clinician; they must not be shared across multiple
staff on the same OS profile, or per-user attribution on the JS trail is lost
until this wiring lands.

### 3.3 Automatic logoff — §164.312(a)(2)(iii) (implemented)

**Current state: implemented and on by default.** An in-app idle watcher
(`src/core/idleLock.js`, `startIdleWatcher`) locks the UI after a configurable
period of inactivity — **enabled by default**, 2-minute default, 1–60 minutes
configurable. It is deliberately suspended while a recording is in progress (a
provider mid-encounter is engaged even during conversational silence), which is
the correct threat model: walk-away *between* patients, not mid-session.

The lock is **cryptographic, not just a screen overlay**: on idle,
`auth_lock_session` (`src-tauri/src/auth.rs`) drops the DB connection pool and
**zeroes the in-memory session DEK**, so once locked there is no live pool and no
key in the process to reach PHI. Resuming requires re-entering the master
password (or the idle-lock PIN, `src-tauri/src/lock.rs`, PBKDF2-HMAC-SHA256 at
210,000 iterations with a throttled/locked-out verify path). The lock overlay
itself cannot be dismissed by Escape or backdrop click.

**Change-auditing (M2):** enabling/disabling the idle lock and changing its
timeout now go through dedicated, audited commands (`lock_enabled_set` /
`lock_timeout_set`), each writing a `config_audit` row (`lock_enabled_changed` /
`lock_timeout_changed`) in the same transaction as the setting, and the KV keys
are write-protected so the generic `kv_set` cannot bypass that audit. Disabling a
required safeguard is therefore provable — see §4.

**Retained operational recommendation:** OS-level screen-lock-on-idle remains a
reasonable defence-in-depth complement, but is no longer the primary control —
the in-app cryptographic lock above is.

---

## 4. Audit controls (§164.312(b), required)

**Status: substantially remediated.** The three gaps first documented in
the `c3e9383` revision of this document (no record-access logging, no
integrity protection on the JS-side trail, silent truncation) have been
fixed in code. Two forgery vectors in the Tauri invoke surface — `audit_append`
and `note_history_append` — have been closed in Commits A and B
(`829b689`, `abc176c`). One related item, real `currentUser()` identity
wiring, remains a separate open item — see the end of this section.

**Current state, two independent trails, both now tamper-evident:**
- `note_history.rs` — DB-backed, SHA-256 hash-chained (`prev_hash`/
  `entry_hash`/`content_hash`), tamper-evident by construction, uncapped.
  Covers the signed-note content lifecycle. Unchanged by this update.
- `src/core/auditLog.js` — a JS array in the KV store, now hash-chained the
  same way: every entry carries `prevHash`/`entryHash`
  (`hashAuditEntry`/`verifyAuditChain` in `src/utils/contentHash.js`, mirroring
  `note_history.rs`'s construction but hashing each entry's own full field
  set rather than a fixed schema, since audit actions carry a variable
  `details` payload). Covers six action types: `note_edited`, `note_signed`,
  `audio_deleted`, `note_exported`, plus the two additions below.

**Gap 1 (record-access logging) — fixed.** Opening an encounter panel now
appends a `record_viewed` entry (`src/entry-solo.js`, gated by
`shouldLogRecordView` in `src/domain/recordAccess.js`), for every encounter
status except `recording` — a fresh recording in progress has no existing
content yet to "view" (the open IS the creation), so that status is
excluded; every other status (`recording_done`, `transcribing`, `draft`,
`signed`, `exported`) is logged, which is a superset of the originally
stated minimum bar ("at least...encounters with signed notes or
transcripts").

**Gap 2 (no integrity protection) — fixed.** `appendAudit` is now async and
hash-chains each entry to the previous one exactly as described above.
Because the chain's correctness depends on durable persistence, writes go
through `kvSetAwait` (fails closed on a write error) rather than the
fire-and-forget `kvSet`, matching the pattern `historyChain.js` already used
for the sign-off chain. All six call sites were updated to `await` the now-
async function.

**Gap 3 (silent truncation) — fixed.** Entries evicted past
`MAX_AUDIT_ENTRIES = 5000` are archived, never discarded: eviction moves the
oldest entries into a parallel KV key (`note_audit_archive_v1::<id>`,
derived from the live key via `archiveKeyFor`), preserving their original
`entryHash`/`prevHash` so the archived tail still verifies as its own valid
chain. The truncation itself is logged as an `audit_log_truncated` system
entry (`actor: 'system'`) chained into the live log, recording exactly how
many entries were evicted and which archive key they went to. The archive
key is durably persisted (`kvSetAwait`) before the shortened live log, so a
crash between the two writes cannot lose the evicted entries.

**Live-log verification note.** Once a truncation has happened, the live
log's own oldest surviving entry legitimately has a `prevHash` pointing at
an entry that now lives only in the archive — checking the live log alone
against `verifyAuditChain`'s default (from-genesis) semantics would
therefore report a false break. `verifyAuditChain` takes an
`{ allowPartial: true }` option for exactly this case (trust the live log's
first entry's stated `prevHash` as an external anchor rather than requiring
it to be null); a caller that wants the actual end-to-end guarantee should
verify `[...archive, ...live]` as one chain instead.

**Regression coverage.** `tests/js/test_auditLog.mjs` (chain construction,
tamper detection across actor/details/action fields, legacy pre-hash-chain
entries, truncation/archival correctness including the live log never
exceeding the cap and every evicted entry being accounted for, fail-closed
behavior on a durable-write failure) and `tests/js/test_recordAccess.mjs`
(the `shouldLogRecordView` status allowlist). Both bug-injected and reverted
against the real implementation to confirm the tests actually fail when the
underlying protection is removed, not just when run against already-correct
code.

**audit_append forgery vector — closed (Commit A `829b689`).** Previously,
`audit_append` was exposed as a Tauri invoke command (`generate_handler!`),
letting the WebView call it with any actor, timestamp, or action string —
forging compliance records in the tamper-evident `note_audit` table. The
command has been removed from the invoke handler. It is replaced by five
narrow server-side commands (`audit_log_record_viewed`, `audit_log_note_edited`,
`audit_log_note_signed`, `audit_log_audio_deleted`, `audit_log_note_exported`)
that derive actor identity server-side from the KV-stored provider profile
(`note_provider_v1::profile`) and timestamp from `crate::time::utc_now_iso()`.
No JS caller can supply actor or timestamp for a new audit row on the Tauri
path. A non-Tauri fallback (dev/test KV path) remains in `auditLog.js` for
the web-preview environment where Tauri is absent.

**note_history_append forgery vector — closed (Commit B `abc176c`).** Previously,
`note_history_append` was exposed as a Tauri invoke command with an open
`entry: object` parameter, letting the WebView inject arbitrary history rows
with any actor, timestamp, or action value — including forging a signed-note
attestation. The command has been removed from the invoke handler. It is
replaced by: (a) `history_note_generated` — actor fixed server-side to
`"AI (Tahlk)"`; (b) `history_note_edited` — actor derived server-side from the
KV provider profile; (c) the `signed` entry is now written atomically inside
`encounters::mark_signed` via `server_sign_history`, collocating the attestation
record and the encounter status flip in a single Rust transaction. JS passes
`action='signed'` to `appendHistoryEntry` on Tauri now throws immediately rather
than silently routing through any open channel.

**Authentication-event logging — added (audit finding H1).** The
credential-verification paths (master-password unlock, recovery-code unlock,
idle-lock PIN verify/set/clear, session lock, password change/reset,
recovery-code regeneration, and the irreversible nuke) now write to a durable
`auth_audit` trail — metadata only (timestamp, event, outcome), no password and
no PHI. It lives in the plain `tahlk_auth.db` wraps DB rather than the encrypted
`tahlk.db` **by necessity**: a *failed* unlock happens while the encrypted DB is
still locked, so it could never be recorded there. This closes the previous blind
spot in which the single most security-critical event in the app — who unlocked
the DEK that protects 100% of the PHI, when, and how many times it was guessed
wrong — left no trace surviving a restart (`throttle.rs` state is in-memory
only). A read command (`auth_audit_list`) exposes the trail for provider/auditor
review.

**Safeguard-configuration auditing — extended (audit finding M2).** `config_audit`
(previously covering only the retention window and litigation hold) now also
records changes to the idle auto-logoff safeguard — `lock_enabled_changed` and
`lock_timeout_changed`, each written in the same transaction as the setting, with
the KV keys write-protected so a generic `kv_set` cannot change the safeguard
without leaving the tamper-evident row. Disabling automatic logoff is therefore
provable (§164.312(a)(2)(iii) + (b)); see §3.3.

**Remaining open item (not part of this remediation):** `currentUser()`
(`src/core/capabilities.js`) still defaults to `null` outside of a real
authenticated-identity implementation, so `actor`/`actorId` on both trails
currently stamp a generic `'provider'` label rather than a specific person
until §3.2 (unique user identification) ships. Hash-chaining makes the
*sequence* of events tamper-evident regardless, but attributing a given
entry to a specific individual still depends on that separate item landing.

---

## 5. Contingency plan (§164.308(a)(7), required)

**Status: no contingency plan previously existed in any form. Documented
here for the first time.**

**Data backup plan (required):** Tahlk Solo has no Tahlk-operated backend
and no built-in backup mechanism — the entire patient record for every
encounter (signed notes, transcripts, audit history, provider/patient
records) lives in a single SQLCipher database file on one device. **The
provider/practice is responsible for backing up this file** using their own
encrypted backup solution (e.g., an encrypted external drive, encrypted
cloud backup software the practice has separately vetted for HIPAA
suitability). Tahlk does not currently provide an in-app export mechanism
for a portable *encrypted* backup (the only export paths today — Flow C —
produce unencrypted note files, not a full encrypted database backup, and are
not a substitute for this).

**Disaster recovery plan (required):** If the device is lost, stolen, or
suffers disk failure, or if the OS keychain entry holding the database
encryption key is corrupted or reset, the database fails closed
(`db_key.rs`: "refusing to open database — restore keychain or reset app
data") with **no in-app recovery path**. Recovery today depends entirely on
whatever backup the provider independently maintained per the plan above. If
no such backup exists, this is an unrecoverable, total loss of every patient
record on that device.

**Emergency mode operation plan (required):** If Tahlk is unavailable during
a live patient encounter (device failure, app crash, etc.), the provider
should fall back to their practice's standard manual/paper documentation
process and backfill the encounter into Tahlk once available, consistent
with normal downtime procedures for any clinical software.

**Testing and revision procedures (addressable):** not yet established. The
provider should periodically verify their own backup of the database file
can actually be restored, not just that a backup file exists.

**Applications and data criticality analysis (addressable):** the SQLCipher
database file is the single critical asset in this application — its loss is
equivalent to losing every patient record the practice has in Tahlk. No
other component (whisper model, app binary, config) contains PHI or is
irreplaceable by reinstalling.

**Planned remediation (tracked, not yet built):** an in-app "export encrypted
backup" feature producing a portable, still-encrypted copy of the database to
a provider-chosen destination, distinct from the unencrypted note-export flow
in Flow C — improving real-world recoverability without contradicting the
local-first architecture.

---

## 6. Security incident procedures and breach notification (§164.308(a)(6); 45 CFR Part 164, Subpart D)

**Status: no incident-response or breach-notification procedure previously
existed. Documented here for the first time.**

**Provider-facing incident reporting:** If a provider using Tahlk suspects a
device compromise, loss, theft, or any other event that may have exposed
patient data, they should report it to Greenbar Systems support as soon as
possible so Greenbar Systems can investigate whether the exposure implicates
anything in Tahlk's own software (as opposed to the provider's own device
security, which is the provider's independent responsibility — see the
Data backup plan and Disaster recovery plan in §5 above, and Flow C's
provider-directed-export responsibility transfer in §2).

**Greenbar Systems' commitment on notice of a suspected incident:**
investigate promptly; if the investigation identifies a vulnerability in
Tahlk itself that could have exposed PHI, notify affected providers so they
can meet their own individual-notification obligations under §164.404 (to
affected patients, without unreasonable delay and within 60 days of
discovery) and, if applicable, §164.408 (to HHS). If Greenbar Systems is
acting as a business associate in a given flow, notification to the covered
entity follows the §164.410 timeline (without unreasonable delay, within 60
days of discovery).

**Division of responsibility:** because Tahlk Solo is local-first with no
Tahlk-operated backend holding PHI, the covered entity (the individual
provider or practice) is generally the party with direct notification
obligations to their own patients under §164.404/408 for an incident
confined to their own device. Greenbar Systems' role above is to support that
obligation by promptly disclosing anything discovered about the software
itself, and to independently evaluate its own notification duties as a
business associate where that role applies — now including the shipped
managed-key proxy in Flow D, for which Greenbar holds the business-associate
role directly (ADR 0006). See the incident-response runbook §6 for how this
splits device-confined vs. note-generation-flow notification duties.

**Audit-trail forgery vectors — closed (relevant to breach notification).**
Two Tauri invoke commands (`audit_append`, `note_history_append`) previously
exposed an open write surface into the tamper-evident audit trails. A
compromised WebView could have used them to inject false records — including
forging a signed-note attestation or suppressing a `record_viewed` entry —
which could have masked unauthorized access to PHI or a falsified clinical
record, making breach discovery and notification harder. Both vectors were
closed in Commits A and B (`829b689`, `abc176c`); see §4 for the full
technical detail. This is recorded in §6 because it directly affects the
reliability of the evidence trail used to determine whether a reportable
breach has occurred.

**Remediation shipped:** the above is now formalized as a standalone
[incident-response runbook](./incident-response-runbook.md) — intake
channel, triage steps, risk assessment, internal escalation, notification
timelines and templates, and closure record-keeping. This section remains
as a summary; the runbook is the operational document to actually follow
when responding to a real incident.

---

## 7. Retention and disposal

**Status: partially implemented (audio only); no full-record retention/
disposal policy previously documented.**

**Current state:** `src/domain/retention.js` implements audio-only retention
(`keep` vs. `delete_on_sign`), purging the raw `.wav` after signing when so
configured. A `delete_encounter` command (`src-tauri/src/encounters.rs`) now
also exists to permanently remove an entire encounter record — the
`encounters` row plus its note text and transcript (the `note_content_v1::`
KV rows) and any residual audio — gated behind an in-app confirmation. It
deliberately does NOT delete `note_history`/`note_audit`/`llm_audit` rows for
that encounter, since none of those tables hold PHI content (metadata and
hashes only); the JS caller appends a final `encounter_deleted` entry to the
audit trail after a successful delete, so the record of the deletion itself
survives even though the clinical content does not. There is still no
configurable time-based retention period and no automatic/scheduled
disposal — deletion today is a manual, per-encounter provider action, not a
policy the app enforces on its own.

**Why the remaining gap is lower severity than Sections 3–6:** indefinite
retention of properly-secured PHI is not itself a HIPAA violation — many
practices are required to retain records for years under state law. The
remaining gap is the absence of a *time-based* retention policy and
automatic disposal tooling, not the ability to delete on request, which now
exists.

**Accepted state (named explicitly):** time-based retention/auto-purge
beyond the existing manual per-encounter delete and the audio keep/
delete_on_sign toggle is the provider's responsibility to manage outside the
app today (e.g., via periodic manual deletion aligned with their state's
medical-records retention requirements).

**Planned remediation (tracked, not yet built):** an optional, provider-
configurable time-based auto-purge policy layered on top of the now-shipped
manual delete capability — see the "No defined, configurable retention
period" finding in the compliance audit report for the fuller design note
on why this should stay opt-in rather than default-on, given the
immutability/audit-integrity design elsewhere in the app.

---

## 8. Encrypted-at-rest, confirmed clean (no action needed)

Re-stated from the prior plaintext-PHI-at-rest sweep for completeness in this
assessment:
- Signed notes, transcripts, audit log, and note/patient history — SQLCipher
  encrypted database.
- Session audio at rest — AES-256-GCM (`0e32611`).
- `recorder.js` — memory-only, never written to disk unencrypted.
- Whisper model file — bundled with the app, never downloaded at runtime, so
  there's no download-cache exposure.
- No crash-reporting SDK is integrated (would be an unaudited third-party
  data flow if one were added — re-assess this document if that changes).

## 9. Out of scope for this assessment

- `tahlk-sync` (Group-tier backend, `server/`) and `src/group/` — frozen per
  ADR 0001, no validated customer, no production deployment. The
  Group-tier-specific findings (S1–S4 and the adjacent Postgres RLS /
  schema-drift items) are tracked separately in
  [`docs/security/pre-deploy-checklist.md`](./pre-deploy-checklist.md) and
  must be independently satisfied — along with a real BAA/PHI-in-transit
  assessment for that service — before it is ever unfrozen or deployed
  against real tenants. This document does not certify that service.
- The managed-key Anthropic proxy described in `MANAGED-KEY-PROXY-CONTRACT.md`
  is a draft contract, not shipped code. It must be assessed under this
  document (see Flow D conditions above) before release, not folded in
  prematurely.

## 10. Review cadence

This document should be re-reviewed:
- Before every production release (see the companion checklist in
  `AUDIT-RESIDUAL-RISK.md` for Items 1 and 2's specific pre-release checks).
- Whenever a new data flow touching PHI is added (new export path, new
  third-party API call, new sync/backup feature, the managed-key proxy
  shipping, etc.) — add it here with the same What it is / Risk
  classification / Mitigations / Conditions structure, don't leave it as a
  verbal decision with no record.
- Whenever `tahlk-sync` moves toward unfreezing — this document's scope
  section explicitly excludes it today; that exclusion must be revisited,
  not silently carried forward.
- Whenever any §3-§7 code remediation ships (in-app PIN/logoff gate, real
  `currentUser()` identity, audit-log hash-chaining or access-event logging,
  encrypted backup export, or record-deletion command) — update the affected
  section's "Current state" and "Planned remediation" text to reflect what
  actually shipped; do not leave a shipped fix described as still-planned.
- At minimum every 6 months, or immediately on any change to the Anthropic
  BAA status (§2 Flow D) — that status must never go stale for longer than
  a routine review cycle, given it gates a live, ongoing PHI disclosure.

**Document history:**
- `461f9e7` — initial version. Consolidates `AUDIT-RESIDUAL-RISK.md`
  Items 1–2, adds Flow D (Anthropic BYOK generation) and Flow F (diagnostics
  export) which were not previously documented as named data flows anywhere
  in the repo, and satisfies the outstanding compliance-documentation
  condition for `AUDIT-RESIDUAL-RISK.md` Item 1.
- `63ffbbc` — updated Flow D with the current real-world BAA status
  (Anthropic BAA application submitted, not yet confirmed executed) per the
  product owner. This is recorded as an open item, not resolved — re-update
  this section once the BAA is confirmed countersigned.
- `c9007ad` — added §3 (access control / person-entity
  authentication: no login gate, no unique user ID, no auto-logoff), §4
  (audit control gaps: no record-access logging, no integrity protection or
  archival on the JS-side audit log), §5 (contingency plan: no backup/
  disaster-recovery documentation previously existed), §6 (incident-response
  and breach-notification procedure: none previously existed), and §7
  (retention/disposal policy beyond the existing audio-purge control). These
  five required or partially-required Security Rule standards were entirely
  absent from this document prior to this update, per the findings of a
  2026-07-13 internal compliance audit (`tahlk_compliance_audit.md`).
  Re-confirmed the Flow D BAA status unchanged (still applied for, not
  executed) with the product owner as of this same date — see §2 Flow D.
- `c3e9383` — cheap documentation-only fixes from the same audit pass
  (no code changes).
- (audit-log hash-chain update) — §4 rewritten from "planned remediation, tracked, not yet
  built" to describe the shipped fix: `auditLog.js` is now SHA-256
  hash-chained (`hashAuditEntry`/`verifyAuditChain` in
  `src/utils/contentHash.js`), truncation past `MAX_AUDIT_ENTRIES` now
  archives evicted entries to `note_audit_archive_v1::<id>` instead of
  discarding them, and opening an encounter now logs a `record_viewed`
  event (`shouldLogRecordView` in `src/domain/recordAccess.js`) for every
  status except `recording`. Covered by `tests/js/test_auditLog.mjs` and
  `tests/js/test_recordAccess.mjs`, both verified against the real
  implementation via bug-injection-and-revert. Flagged the still-open
  `currentUser()` identity gap (§3.2) as a separate item this change does
  not resolve.
- (2026-07-18 update) — Flow D status advanced: the Greenbar↔Anthropic BAA
  was **executed 2026-07-18** (previously "applied for, not yet executed");
  ZDR provisioning on the dedicated Anthropic organization behind the future
  managed-key proxy is now the outstanding technical prerequisite and is
  pending Anthropic approval. Separately, the provider↔Greenbar BAA and EULA
  moved into **attorney drafting the week of 2026-07-13**; neither is executed
  with any practice yet. Updated: §2 top-of-table Flow D row, §2 Flow D
  "Current real-world status" and "Action items" bodies.
- `829b689` (Commit A) — closed the `audit_append` forgery vector: removed
  the open `audit_append` command from the Tauri invoke handler; replaced with
  five narrow server-side commands whose actor and timestamp are derived
  server-side, not supplied by the WebView. §4 updated to document this fix
  and its relevance to audit-trail integrity.
- `abc176c` (Commit B) — closed the `note_history_append` forgery vector:
  removed the open `note_history_append` command from the Tauri invoke handler;
  replaced with narrow server-side commands for `generated`/`edited` entries and
  moved the `signed` history entry into `encounters::mark_signed` as an atomic
  Rust transaction. §4 and §6 updated to document both fixes and the
  breach-notification relevance of reliable audit-trail evidence. Updated
  "As of commit" to `abc176c`.
- (2026-07-24 update) — Flow D reconciled with [ADR 0006](../adr/0006-enforce-baa-gate-managed-key.md):
  the managed-key proxy is now **built and shipped** and BYOK is **retired**
  (`baa::GATE_ENABLED = true`, gate enforced in production), correcting the
  prior "not built / BYOK-during-beta" framing. The **executed contracts remain
  pending** (Greenbar↔Anthropic ZDR provisioning; provider↔Greenbar BAA + EULA),
  so the material open item flipped from *code* to *paper*, and the test-data-only
  guardrail is now **procedural, not technical** — flagged prominently because the
  enforced gate must not be mistaken for that safeguard. Updated: §2 Flow D heading
  + anchor, the §2 table row, the Flow D body (current implementation / risk
  classification / status / action items / conditions), and §6's business-associate
  language. Resolves the ADR-0006 ↔ risk-assessment inconsistency flagged in the
  incident-response runbook §6.
- (2026-07-24, audit finding H2) — **§3 reconciled with shipped code.** §3.1–§3.3
  previously described the person/entity authentication gate and the automatic
  logoff as *absent* ("Tahlk has no application-level login, PIN, passphrase, or
  biometric gate"; "No idle-timeout … exists anywhere in the app"). Both are
  false: first-open authentication (ADR 0004 — master password, PBKDF2-210k,
  AES-256-GCM DEK wrapping, recovery codes; plaintext keychain DEK deleted once
  configured) and the idle auto-logoff (on by default, cryptographic — zeroes the
  session DEK) have shipped and are enforced. §3.1/§3.3 rewritten to describe the
  implemented controls with the biometric-unlock residual named; §3.2 updated to
  "partially closed" (authenticated identity + server-derived Rust audit actor;
  JS `currentUser()` wiring still open). §4 gained the H1 authentication-event
  trail (`auth_audit`) and the M2 idle-lock config auditing. "As of commit" bumped
  to `5885922`. This corrects the §164.316 documentation-integrity gap where the
  operative risk assessment understated the app's actual (stronger) posture.
  **Not covered here:** the ADR-0006 / `config.rs` "ZDR-covered" wording still
  asserts ZDR as active while §2 Flow D correctly records it as pending Anthropic
  approval — that overclaim is tracked with the C1 release-blocker decision, not
  changed in this documentation pass.
