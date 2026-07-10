# Tahlk Solo — HIPAA Security Risk Assessment

**Status:** Active compliance record
**Scope:** Solo tier desktop application only (`src/group/` and `server/` —
the `tahlk-sync` Group-tier backend — are explicitly out of scope; that
service is frozen per [ADR 0001](../adr/0001-freeze-group-tier-and-sync.md)
and has zero validated demand or production deployment as of this writing).
**As of commit:** `63ffbbc`
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
below.

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

## 3. Encrypted-at-rest, confirmed clean (no action needed)

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

## 4. Out of scope for this assessment

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

## 5. Review cadence

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
