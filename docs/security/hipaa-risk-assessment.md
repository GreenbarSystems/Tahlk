# Tahlk Solo — HIPAA Security Risk Assessment

**Status:** Active compliance record
**Scope:** Solo tier desktop application only (`src/group/` and `server/` —
the `tahlk-sync` Group-tier backend — are explicitly out of scope; that
service is frozen per [ADR 0001](../adr/0001-freeze-group-tier-and-sync.md)
and has zero validated demand or production deployment as of this writing).
**As of commit:** `c9007ad`
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
| D | Note generation (Anthropic API, BYOK mode) | Patient conversation transcript | In transit (network) | Yes (TLS) in transit; **BAA with Anthropic applied for, not yet confirmed executed** — see [§2 Flow D](#flow-d--note-generation-via-anthropic-byok-mode) |
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

### Flow D — Note generation via Anthropic (BYOK mode)

**What it is.** `generate_note` (`src-tauri/src/notes.rs:309`) sends the
session transcript — PHI — to Anthropic's API to produce the structured
clinical note, using the provider's own Anthropic API key (Bring-Your-Own-Key
mode; this is the only mode currently shipped — the managed-key proxy
described in `MANAGED-KEY-PROXY-CONTRACT.md` is a v1 draft, not yet built).

**Risk classification:** Conditionally permitted third-party PHI disclosure —
gated, not blanket-accepted. **Condition currently unmet / in progress:** the
BAA with Anthropic has been applied for but is not yet confirmed executed as
of this writing (see below) — this flow should be treated as an open item,
not a fully closed one, until that's confirmed.

**Why sending PHI to Anthropic is not an automatic compliance violation:**
HIPAA permits disclosing PHI to a third party that has signed a Business
Associate Agreement (BAA) as your Business Associate. It does **not** permit
sending PHI to a party with no BAA in place. Tahlk's mitigation is a hard
technical gate, not a policy statement:

- `require_ack` (`src-tauri/src/baa.rs:113`) is called at the very top of
  `generate_note` (`notes.rs:320`) — strictly before the API key is read,
  before the HTTP client is built, and before the transcript is touched in
  any way. If the provider has not acknowledged a current BAA attestation,
  the call is refused with `AppError::BaaRequired` and **no transcript
  content leaves the device.** This ordering is deliberate and documented
  inline in the source (`notes.rs:316-320`).
- The transcript is TLS-encrypted in transit to Anthropic (standard HTTPS).
- Prompt-injection hardening wraps the transcript in tagged delimiters before
  it's sent (audit finding H6, `notes.rs:336-340`).
- Upstream error handling never surfaces the request or response body into
  logs or the app's error surface — only an HTTP status code or a fixed
  generic string (audit findings M9/M10, `notes.rs:408-422`) — so a failed
  generation call can't leak transcript content through the error path.

**Current real-world BAA status (as of this document, self-reported by the
product owner, not independently verified by code inspection — code cannot
confirm the state of a legal agreement):** an application for a BAA with
Anthropic has been submitted; **it is not yet confirmed executed/countersigned**
as of this writing. This is a live gap, not a closed item — see action items
below. **Re-confirmed unchanged (still applied for, not executed) by the
product owner on 2026-07-13** — do not treat the passage of time alone as
progress; the next update to this line must reflect an actual status change,
not merely a later re-confirmation of the same status.

**What this means for your BAA obligations (action item, not a code
concern):** Tahlk's technical gate only enforces that *some* acknowledgment
exists in the local database — it does not itself constitute or replace a
signed BAA between the provider (or your organization, if Tahlk is acting as
the Business Associate here) and Anthropic. **Confirm and keep current:**
(1) which entity is the Covered Entity and which is the Business Associate in
this flow for your deployment model, (2) **track the pending Anthropic BAA
application above through to actual execution, and re-run this section's
status line once it's confirmed countersigned — do not treat "applied" as
equivalent to "in effect" for compliance purposes**, (3) confirm a real,
signed BAA with Anthropic is in effect for every account using BYOK note
generation once executed, and (4) that the in-app acknowledgment
(`baa_ack_set`, `src-tauri/src/baa.rs:143`) is kept in sync with that
real-world agreement — the gate trusts the local
flag; it cannot verify the underlying paperwork exists.

**Conditions to remain accepted:** `require_ack` must remain the first
statement in `generate_note` (before any key read, client build, or
transcript handling); the BAA acknowledgment flow must remain a hard `Result`
gate (`AppError::BaaRequired`), not a soft warning; the managed-key proxy, if
and when shipped, must be re-assessed under this document before release —
it changes the disclosure boundary (Tahlk's own key + proxy become a
Business Associate in the chain, per `MANAGED-KEY-PROXY-CONTRACT.md` §1's own
banner: *"The proxy is a HIPAA Business Associate... MUST NOT log, persist,
or cache request/response bodies."*).

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

**Status: open gaps, documented here for the first time as of `c9007ad`.**
These are named, *required* implementation specifications under the
Security Rule — not addressable/optional — and this document previously did
not address them. That was a documentation gap in its own right, independent
of whether the underlying code gap is remediated on any particular timeline.

### 3.1 Person or entity authentication — §164.312(d) (required)

**Current state:** Tahlk has no application-level login, PIN, passphrase, or
biometric gate. `db_key.rs`'s `load_or_generate_dek()` fetches the SQLCipher
database key from the OS keychain automatically at launch with no user-
entered secret — the database opens for whoever can launch the app under the
currently logged-in OS account. `secrets.rs` only manages the provider's own
Anthropic API key (authenticating the *app* to Anthropic), not a person to
the app.

**Accepted control (named explicitly, not silently relied upon):** Tahlk
designates the operating system's own session login (Windows/macOS user
account authentication) as its person/entity authentication boundary for
Solo tier. This is a real control when properly configured, but it is
external to Tahlk and Tahlk cannot verify it is in place on any given
device.

**This places an explicit operational requirement on the provider/practice**
(an Administrative Safeguard the covered entity must implement per
§164.308(a)(5)(ii)(D), password management — addressable but expected absent
a documented equivalent): OS-level login must be enabled on any device
running Tahlk, with a non-trivial password/PIN, and shared or guest accounts
must not be used to run the app.

**Planned remediation (tracked, not yet built):** an in-app PIN/passphrase
gate on launch and on resume-from-idle, independent of OS login, removing
reliance on an external, unverifiable control. Until shipped, the OS-login
boundary above is the accepted control and must be operationally enforced by
the practice.

### 3.2 Unique user identification — §164.312(a)(2)(i) (required)

**Current state:** `src/core/capabilities.js`'s Solo-tier default is
`currentUser: () => null`. `src/core/auditLog.js`'s `actor` field falls back
to the hardcoded literal string `'provider'` whenever no user object exists
— which, in Solo mode today, is always. Every audit-log entry produced by
any installation is attributed to that same static string.

**Accepted design assumption (named explicitly):** Tahlk Solo is licensed
and intended to be used by exactly one identified clinician per
installation. The `'provider'` audit-log actor string is intended to
represent that single person, established via the existing provider-profile
setup (name/NPI already captured in `kv` during onboarding) — not a
generically anonymous placeholder. **This assumption must hold operationally:**
Solo installations must not be shared across multiple staff members on the
same machine/profile. If multi-staff shared-device usage is a real deployment
pattern, this assumption is violated and a real per-user identifier becomes
required, which converges with the 3.1 authentication gate.

**Planned remediation (tracked, not yet built):** wire `currentUser()` to
read the existing provider-profile record so the audit trail records the
actual configured provider name rather than a static placeholder string.

### 3.3 Automatic logoff — §164.312(a)(2)(iii) (required)

**Current state:** No idle-timeout or inactivity-based session termination
exists anywhere in the app (repo-wide search covers both the Rust backend
and JS frontend; the only idle timeouts found govern database connection
pooling and HTTP client behavior, not user sessions). Once launched, Tahlk
remains fully accessible indefinitely regardless of idle duration.

**Interim compensating control (operational, provider-managed, effective
immediately at no engineering cost):** until an in-app timeout ships,
practices must configure OS-level screen-lock-on-idle (standard, built into
Windows and macOS) on any device running Tahlk, at an interval consistent
with their workstation security policy (commonly 10–15 minutes in clinical
settings). This is not equivalent to an in-app control — it depends on the
same external, Tahlk-unverifiable boundary as 3.1 — but it is a real,
immediately available mitigation and must be treated as a required setup
step for any Tahlk deployment until superseded.

**Planned remediation (tracked, not yet built):** an in-app idle timer
(configurable, default 10–15 minutes) that locks the UI and requires
re-entry of the 3.1 PIN/passphrase (once shipped) before further PHI is
displayed.

---

## 4. Audit controls (§164.312(b), required)

**Status: substantially remediated.** The three gaps first documented in
the `c3e9383` revision of this document (no record-access logging, no
integrity protection on the JS-side trail, silent truncation) have been
fixed in code. One related item, real `currentUser()` identity wiring, is a
separate open item — see the note at the end of this section.

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
business associate where that role applies (e.g., the Anthropic-relay flow in
Flow D, or a future managed-key proxy).

**Planned remediation:** formalize the above into a standalone incident-
response runbook (intake channel, triage steps, internal escalation, and
template provider notification) rather than leaving it as prose in this
document only.

---

## 7. Retention and disposal

**Status: partially implemented (audio only); no full-record retention/
disposal policy previously documented.**

**Current state:** `src/domain/retention.js` implements audio-only retention
(`keep` vs. `delete_on_sign`), purging the raw `.wav` after signing when so
configured. There is no capability to delete an entire encounter record —
signed note, transcript text, and hash-chained history persist indefinitely
with no exposed deletion path, no configurable retention period, and no
disposal procedure.

**Why this is lower severity than Sections 3–6:** indefinite retention of
properly-secured PHI is not itself a HIPAA violation — many practices are
required to retain records for years under state law. The gap is the
*absence of a documented retention/disposal policy and of any tooling to
act on one*, not the retention itself.

**Accepted state (named explicitly):** retention and disposal of the
full encounter record beyond the existing audio-purge control is the
provider's responsibility to manage outside the app today (e.g., via device-
level deletion or disposal procedures aligned with their state's medical-
records retention requirements and any individual patient deletion request
they are obligated to honor).

**Planned remediation (tracked, not yet built):** a "delete this encounter
permanently" command removing the note, transcript, hash-chain entries, and
any residual files for a given encounter, gated behind confirmation and
logged as a `record_deleted` audit event once Section 4's audit-log
remediation is in place.

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
- (this update) — §4 rewritten from "planned remediation, tracked, not yet
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
