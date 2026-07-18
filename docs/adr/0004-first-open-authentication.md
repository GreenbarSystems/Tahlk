# ADR 0004 — First-open authentication (device-local password + biometric opt-in + three recovery codes)

- **Status:** Proposed — 2026-07-18
- **Deciders:** product owner + engineering
- **Supersedes:** none
- **Related:** ADR 0003 (BAA gate soft-disable); `docs/security/hipaa-risk-assessment.md` §3.1 (idle-lock) and §3.2 (`currentUser()` gap); `docs/security/data-flow-and-security-controls.md` §1 (no Tahlk-operated server in the Solo data path); `src-tauri/src/db_key.rs` module doc (residual risk: "device theft plus keychain export"); `src-tauri/src/lock.rs` (existing PIN idle-lock).

## Context

Tahlk today has three independent local secrets in the OS keychain — the
Anthropic API key (`secrets.rs`), the SQLCipher database encryption key
(`db_key.rs`), and the idle-lock PIN hash (`lock.rs`). The DEK is loaded
unconditionally at process start by `load_or_generate_dek()`; there is no
gate between "Tahlk launches" and "the encrypted database is open." The
existing idle-lock PIN (`src/solo/lockScreen.js`) is, by its own module
comment, aimed at "a passerby at an already-running, unattended laptop, not
a sustained offline attack" — it renders as an overlay on top of an
*already-authenticated* session.

That leaves two named threats uncovered:

1. **First-open on a fresh install.** Anyone who obtains the clinician's
   unlocked laptop, or who gets past a weak OS password, opens Tahlk and
   walks straight into either onboarding (fresh install) or the app shell
   (existing install) with no application-layer gate at all.
2. **The `currentUser()` gap.** `hipaa-risk-assessment.md` §3.2 already
   flags that Tahlk has no unique user identity at the app layer — audit
   entries can attribute *what* happened, but not to *whom* on this
   install. There is currently no place in the product where the clinician
   proves they are the account-holder before touching PHI.

`db_key.rs`'s own module comment names this residual risk explicitly:

> "If the OS keychain is compromised the DB is too; that is an accepted
> trade-off vs. prompting the clinician for a passphrase on every launch.
> FDE at the OS level (FileVault/BitLocker) is a recommended complementary
> control, not a substitute — **device theft plus keychain export is the
> residual risk.**"

That trade-off was defensible for the test-data-only beta; it is not
defensible for real PHI. The managed-key rollout (ADR 0003 unfreeze
criterion #1) is the moment the data in flight upgrades to real PHI, and
therefore the moment the "no application-layer authentication" trade-off
has to be replaced with a real control.

## Decision

Add an application-layer authentication gate that runs **before the app
shell renders** at every process start, backed by a password the clinician
sets at first-open. Preserve `data-flow-and-security-controls.md` §1's
"no Tahlk-operated server in the Solo data path" invariant — nothing in
this ADR introduces a network dependency or a server-side identity
service.

### Cryptographic model

The DEK stops being stored plaintext-in-keychain. It is instead stored
**wrapped** (encrypted at rest), with multiple independent wrapping keys,
each of which can independently unlock it:

- **Password-derived KEK** (primary, always). PBKDF2-HMAC-SHA256 via
  `ring::pbkdf2` — the same algorithm and dependency already used by
  `lock.rs` and `audio_crypto.rs`, no new crate. Iteration count matches
  `lock.rs`'s 210,000 (OWASP 2023 minimum for PBKDF2-HMAC-SHA256),
  targeting ~300–500 ms verification on a mid-range laptop. Per-install
  random 16-byte salt, stored alongside the wrapped DEK. **See
  Alternatives Considered for the Argon2id comparison** — PBKDF2 is chosen
  for dependency parity with the existing crypto surface, not because it
  is stronger.
- **Biometric-protected keychain entry** (optional, opt-in at first-open).
  On macOS and Windows, a copy of the plaintext DEK is stored in a
  keychain item whose access control requires user presence via the OS
  biometric authenticator (Apple Secure Enclave on macOS, Windows Hello /
  TPM on Windows). The biometric template never leaves the OS; Tahlk
  never sees it. On Linux, this option is not offered — the desktop
  Secret Service API has no standardized biometric access-control
  attribute, and we will not fake it. Linux users get password +
  recovery codes only.
- **Three recovery-code-derived KEKs** (required, generated at
  first-open). Three independent 24-character base32 codes (with a
  Crockford-base32 checksum group so typos are caught before Argon2/PBKDF2
  work is spent), each of which derives its own KEK via the same PBKDF2
  parameters as the password. Three wrapped copies of the DEK — any one
  code recovers.

All wrapping keys wrap the **same** DEK. The DEK itself is unchanged
across wrappings, so migration (see below) preserves the existing
SQLCipher database bit-for-bit.

The wrapped DEK blobs live in a new Rust-owned SQLite table
(`auth_dek_wraps`) in the *application data directory*, **not** inside
the encrypted SQLCipher database — because the DEK has to be unwrapped
*before* the encrypted DB can be opened. The biometric wrap is the sole
exception: it stays in the OS keychain, protected by the OS's biometric
access-control attribute, matching the existing pattern in `keychain.rs`.

### The three keychain items (updated)

`keychain.rs`'s module doc names the three keychain items and pins their
distinctness as a security invariant. This ADR adds a fourth and updates
the third:

- `anthropic_api_key` — unchanged (or removed under managed-key; separate
  decision, see ADR 0003 unfreeze criterion #1).
- `db_encryption_key` — **repurposed**. No longer holds plaintext DEK.
  Under this ADR, if biometric unlock is enabled on this install, this
  item holds the biometric-protected plaintext DEK; if biometric unlock
  is disabled, this item is deleted at migration time and re-created only
  if the clinician later enables biometric unlock. The plaintext DEK is
  never in the keychain absent an explicit biometric access-control
  attribute.
- `lock_pin_hash` — unchanged. Idle-lock PIN stays exactly as it is.
- `auth_password_hash` — **new**. Not used for DEK derivation (the KEK
  itself derives from the password directly for wrapping), but stored
  alongside for the sign-in verification step, so a wrong-password
  attempt fails cheaply *before* attempting to unwrap the DEK. Same
  PBKDF2 parameters. This mirrors the pattern `lock.rs` already uses for
  the PIN.

Every claim in `keychain.rs`'s "do not consolidate" invariant continues
to hold — each secret stays in its own keychain item with its own
distinct user constant.

### First-open flow

Runs **before** `renderOnboarding()` in `src/solo/onboarding.js`. The
existing onboarding flow is unchanged; a new pre-flow, gated by
`isAuthConfigured()`, runs first.

**Screen A — Set your Tahlk password.**

- Username field (defaults to OS username, editable; display-only, not a
  security control).
- Password field with a strength meter; minimum 12 characters; blocked
  against a bundled list of the 10,000 most common passwords (SecLists,
  vendored at build time — no runtime network call).
- Confirm password.
- Explanatory copy: password is local to this device; Greenbar never sees
  it; can't reset it; recovery codes are the fallback.

**Screen B — Enable biometric unlock (optional).**

- Only shown on macOS and Windows. Not shown on Linux.
- One-click: "Also unlock with Touch ID" / "Also unlock with Windows
  Hello." Explains that the biometric template never leaves the device.
- Skippable. Skipping leaves the biometric keychain item uncreated.

**Screen C — Save your three recovery codes.**

- Three 24-character base32 codes shown **one at a time**, each in a
  monospace group of six 4-character chunks.
- For each code, three save-affordances: **Copy to clipboard**, **Save
  to my password manager** (opens a URL scheme detected at runtime — 1Password,
  Bitwarden, macOS Passwords app on macOS 14+), **Download printable PDF**.
- The "next code" button is disabled until at least one save-affordance
  has been used for the current code.
- After all three, a summary screen listing which affordance was used
  for each code, with a recommendation that at least two of the three
  live in different physical locations.
- Final button: **I've saved my recovery codes — continue**. Only
  enabled after the summary is acknowledged.

**Screen D — Prompt-to-self email.** *(Optional, off by default.)*

- Copy: "Where did you save your recovery codes? Fill in this reminder to
  yourself and we'll email it to you. Greenbar never sees your answer —
  we compose the email in Tahlk and hand it to your default mail client
  as a draft you send yourself. This gives future-you a search-findable
  note about where the codes are, without any secret ever leaving your
  device."
- Three text boxes labeled "Code 1 saved to:", "Code 2 saved to:", "Code
  3 saved to:" (e.g. "1Password vault 'Work'", "printed card in filing
  cabinet, top drawer", "safe deposit box").
- One button: **Open in mail** — populates the OS `mailto:` handler with
  the clinician's onboarding email as recipient, a subject line, and the
  three location strings as the body. Tahlk never sees the email; the
  content is a `mailto:` URL handed to the OS.
- Skippable. If skipped, offered again in Settings later.

**Screen E onward — the existing `renderOnboarding()`** proceeds as
today (provider profile, then Anthropic API key under BYOK, or nothing
in the managed-key case where the API key step disappears entirely per
`MANAGED-KEY-ROLLOUT.md`).

### Subsequent-open flow

Every launch after the first, before the app shell renders:

1. Sign-in screen shown: username pre-filled, password field, **Sign in**
   button, **Unlock with Touch ID / Windows Hello** button (if enrolled),
   small **Forgot password?** link.
2. On biometric success: unwrap DEK from the biometric-protected
   keychain item → open SQLCipher → render app.
3. On password success: PBKDF2-verify against `auth_password_hash` →
   derive KEK from password → unwrap DEK from `auth_dek_wraps` row for
   the password wrap → open SQLCipher → render app.
4. On failure: generic error ("Incorrect password"), never leaking
   whether the username exists.
5. Reuses `lockScreen.js`'s existing failed-attempt lockout logic
   (5 tries → 30s cooldown, doubling per repeat lockout) — same code
   path, applied to the sign-in step. `lockScreen.js`'s comment about
   the lockout being "cheap defense in depth against someone with
   physical access trying to brute-force a short PIN" applies verbatim
   here.

### Forgot-password flow

**Forgot password?** opens a modal with three options:

1. **Use biometric unlock** — only shown if biometric was enrolled but
   the clinician forgot the password. Unwraps DEK from biometric
   keychain item, then immediately routes to a **Set a new password**
   screen, then re-wraps the DEK under the new password's KEK.
2. **Enter a recovery code** — accepts any of the three codes,
   PBKDF2-derives the KEK from it, unwraps that recovery wrap of the
   DEK, then routes to **Set a new password** and re-wraps under the
   new password. The used recovery code is **not** re-generated
   automatically; the clinician is prompted "you have two recovery
   codes left — regenerate a fresh set?" and given the option to
   redo Screen C. The two unused codes remain valid; regenerating
   replaces all three.
3. **Reinstall and start fresh** — big red confirmation screen ("This
   will permanently delete every note, recording, and patient record on
   this computer. This cannot be undone. Type DELETE to confirm."). On
   confirmation, Tahlk wipes its SQLCipher DB file, all `auth_dek_wraps`
   rows, all Tahlk keychain items (`auth_password_hash`, `db_encryption_key`,
   `lock_pin_hash`, `anthropic_api_key`), and quits. Next launch is a
   fresh first-run.

### Relationship to existing controls

- **Idle-lock PIN** (`src/solo/lockScreen.js`, `src-tauri/src/lock.rs`) —
  unchanged. Different threat model (walk-away mid-session), different
  factor (short PIN), different UX (overlay on authenticated session).
  Continues to be a lightweight quick-relock inside an authenticated
  session; do not remove.
- **BAA acknowledgment gate** (`src-tauri/src/baa.rs`, ADR 0003) —
  unchanged. Runs at note-generation time, layered on top of a
  successful sign-in.
- **`currentUser()` gap** (`hipaa-risk-assessment.md` §3.2) — partially
  closed. This install now has a unique authenticated user identity
  (username + password + wrap-of-DEK), and audit entries can attribute
  actions to that identity. The remaining gap is org-wide identity
  (multiple clinicians on multiple installs sharing a practice-level
  identity space); this ADR is device-scoped and does not address that.

## Consequences

### Positive

- **The `db_key.rs` residual risk (device theft plus keychain export) is
  materially reduced.** An attacker with the disk image plus the
  keychain can no longer read the DB; they also need the password (or
  the biometric, or a recovery code).
- **The `hipaa-risk-assessment.md` §3.2 `currentUser()` gap partially
  closes.** Audit entries can now attribute to an authenticated user.
- **The Solo product's §1 architectural invariant is preserved.** No
  Tahlk-operated server enters the data path. No new third party.
- **Migration is safe.** The DEK itself doesn't change; only its
  wrapping does. Existing SQLCipher databases open with the same key
  after migration.

### Negative / accepted

- **Forgetting the password AND losing all three recovery codes AND
  disabling biometric (or being on Linux, where biometric isn't offered)
  = data loss.** This is by design — recovery through Greenbar would
  require Greenbar to hold or be able to hold a copy of the DEK, which
  would break the §1 invariant. Three recovery codes plus biometric on
  supported platforms is our best-effort mitigation.
- **Every process start now takes a password entry.** Biometric unlock
  brings this back to ~one tap on supported platforms; on Linux and on
  installs where the clinician declined biometric, it is a real UX cost.
- **Linux users get a materially different experience** (no biometric
  option). This is honest — the platform capability isn't there — but
  worth naming in customer-facing docs.
- **The bundled 10k-common-passwords list adds ~100 KB to the app
  binary.** Acceptable; SecLists' `10k-most-common.txt` is well under
  that.
- **The `auth_dek_wraps` SQLite file is a new, sensitive on-disk
  artifact.** It contains no plaintext material — only PBKDF2 salts,
  ciphertexts, and metadata — but its integrity is now a control:
  corruption or deletion of the row makes the DB unopenable via that
  wrap. Backup guidance in customer docs must call this out.
- **Password reset via recovery code invalidates only the *used* code.**
  We deliberately keep the two unused codes valid, so a clinician who
  used one code to recover isn't immediately down to zero backups. The
  "regenerate all three" prompt is offered but not forced. This is a
  usability-over-strict-hygiene call; ADR review should confirm.

### Explicitly rejected during design

- **Server-side identity / account recovery.** Would break the §1
  invariant. Not built.
- **Security questions (KBA).** NIST SP 800-63B has recommended against
  KBA since 2017; real-world entropy is too low and answers are often in
  data-broker files. Not built.
- **Silent cloud backup of recovery codes** (iCloud/Google Drive/Dropbox).
  Introduces a third party into a compliance-sensitive path. Not built.
- **Vendor-side (Greenbar) recovery escape hatch.** Any mechanism that
  lets Greenbar recover the DEK is a mechanism a subpoena or a
  compromised signing key can also invoke, and it makes the "we can't
  reset it" copy dishonest. Not built.
- **Argon2id in place of PBKDF2-HMAC-SHA256.** Argon2id is the modern
  best-practice password-hashing function (memory-hard, resistant to
  GPU/ASIC attacks in a way PBKDF2 is not). We chose PBKDF2 anyway
  because `ring` is already a direct dependency (via `audio_crypto.rs`
  and `lock.rs`) and offers PBKDF2 but not Argon2id; adding an Argon2
  crate would expand the dependency surface without a corresponding
  improvement in the *actual* threat model here (a determined attacker
  with GPU rigs is not our named adversary — an opportunistic laptop
  thief is). This decision should be revisited if the threat model
  formally expands to include nation-state-tier offline attackers.

## Migration for existing installs

Existing beta testers have a plaintext DEK in the OS keychain and no
password set. First launch after the ADR-0004 update ships:

1. Detects `auth_password_hash` is not set → this is a pre-ADR-0004
   install.
2. Shows a one-time modal: *"Tahlk now requires a password on this
   computer. This protects your patient records if someone else opens
   your laptop. This takes about 30 seconds and doesn't touch any of
   your existing notes or recordings."*
3. No skip button. The clinician sets password → is offered biometric
   (macOS/Windows) → sees the three recovery codes flow.
4. In the same transaction, Tahlk reads the plaintext DEK from the old
   `db_encryption_key` keychain item, wraps it under the new
   password-KEK (and biometric access-control keychain item, and each
   recovery-code KEK), writes `auth_dek_wraps`, deletes the plaintext
   `db_encryption_key` keychain item, sets `auth_password_hash`.
5. App opens as normal. The clinician's existing notes, recordings,
   and audit history are untouched.

The migration is transactional at the Rust level: either every wrap is
written AND the plaintext keychain item is deleted, or nothing changes
and the app rolls back to pre-migration state so the clinician can
retry. This is critical — a half-migration where the plaintext is
deleted but the wraps failed would brick the install.

## Rollout gates

Ship in this order; do not skip stages:

1. **ADR merged, code not yet written.** This document lands; attorney
   reviewing the BAA/EULA this week (per user, 2026-07-13) can weigh in
   on the authentication design before code exists.
2. **Rust `auth.rs` module built and tested behind a feature flag** —
   `auth_v1_enabled: bool = false`. Full unit tests for wrap/unwrap,
   PBKDF2 parameter parity, recovery-code checksum validation, and the
   transactional migration path.
3. **JS screens built against the tested Rust**, feature flag still
   off. Reuses `lockScreen.js`'s modal shell and lockout logic.
4. **Feature flag turned on for one internal install** (Ryan's own
   dev machine). Verifies migration on a real install with real data.
5. **Feature flag turned on for beta cohort**, coordinated with the
   `MANAGED-KEY-ROLLOUT.md` rollout so real-PHI use and
   authentication ship together — not one before the other.
6. **Feature flag removed** after one full month of beta operation
   with no migration incidents.

## Unfreeze / revisit criteria

Revisit this ADR if any of the following changes:

1. **The threat model formally expands to nation-state-tier offline
   attackers.** Reconsider Argon2id vs. PBKDF2.
2. **Cross-device sync becomes a product requirement.** Device-local
   auth cannot satisfy this; a real identity service would be needed,
   which is a §1 invariant change requiring its own ADR.
3. **A jurisdiction Tahlk operates in requires vendor-side account
   recovery** (some healthcare-adjacent regulations may). The "no
   Greenbar recovery" stance would need explicit legal review.
4. **Real-world beta data shows recovery-code loss exceeding ~5% of
   installs per year.** The three-code design is intended to keep this
   well below 1%; if it doesn't, consider the Shamir trusted-contact
   option previously deferred.
