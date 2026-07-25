# Deferred hardening — implementation plan

Follow-ups from the independent (de-biased) security re-review that were **not**
shipped in the #81–#93 batch because each needs an environment this repo's CI
does not provide — a runnable app and/or the ability to add & lock a new crate —
or a backward-compatible migration whose failure mode is "no one can unlock."

Each item below is scoped so it can be picked up cold: the blocker, the design,
the files, the migration/crash-safety story, the test plan, and the exit
criteria.

> **Update:** two of these have since shipped once it was clear CI could gate
> them without a running app: **G2** (server-side sign hash, #7) in PR #95 and
> **H2** (AAD-bound DEK wraps, #13) in PR #94. Their sections below are retained
> as an implementation record and marked ✅ SHIPPED. The genuinely-remaining
> items are **E2** and **H3** (each needs an environment this repo's CI lacks)
> plus the Tier-4 perf nits.

Ordering recommendation for what remains: **H3 → E2** (increasing blast radius),
with the Tier-4 perf nits done opportunistically whenever the relevant file is
open.

---

## E2 — True DEK rotation (finding #5)

**Goal.** Make "the DEK may be compromised" recoverable **without destroying
data**. Today `change_password` re-wraps the *same* DEK; the only fresh-DEK path
is `nuke_and_reinstall`, which wipes records.

**Why it was deferred.** The audio-at-rest key is *derived from* the DEK
(`audio_crypto::derive_audio_key`), so naively rotating the DEK orphans every
`.wav.enc`. Re-encrypting all audio inline is an O(files) crash-safe migration,
and the whole flow re-keys the live SQLCipher DB — untestable without running the
app.

### Recommended design — two phases

**Phase 1 (prerequisite): decouple the audio key from the DEK.**
Introduce an *audio master key* (AMK): a random 32-byte key, **wrapped under the
DEK** and stored in the wraps DB (a new `auth_dek_wraps` row `wrap_type =
'audio_master'`, reusing `wrap_dek`/`unwrap_dek`). `audio_crypto::audio_key()`
then unwraps the AMK instead of deriving from the DEK.

- **Migration (idempotent):** on first run after this ships, if no `audio_master`
  wrap exists, set `AMK := derive_audio_key(current_dek)` and wrap it under the
  current DEK. This makes the AMK *bit-identical* to what existing `.wav.enc`
  files were encrypted with, so nothing needs re-encrypting.
- After this, the AMK is DEK-independent: rotating the DEK only re-wraps the AMK,
  it never touches an audio file.
- Files: `audio_crypto.rs` (unwrap-AMK path + migration), `auth.rs`
  (`audio_master` wrap type in the allowlist), tests.

**Phase 2: rotate the DEK.** New command `auth_rotate_dek(app, current_password)`
(Settings → "Replace encryption key", framed as compromise recovery):

1. Verify password; unwrap old DEK (`Zeroizing`). Mint fresh DEK (`getrandom`,
   `Zeroizing`).
2. **Re-key the record DB via a staged copy**, reusing the existing crash-safe
   pattern (`migrate_plaintext_to_encrypted` / restore): `sqlcipher_export` the
   live DB into `tahlk.db.rekey-pending` keyed with the **new** DEK; verify it
   opens; do **not** touch the live DB yet. (Do not use in-place `PRAGMA rekey` —
   a crash mid-rekey corrupts the only copy.)
3. Re-wrap under the new DEK **and regenerate recovery codes**: compute new
   `password`/`recovery_1..3` wraps + the `audio_master` wrap, all for the new
   DEK, into a staging structure.
4. **Apply at next launch**, extending `apply_pending_restore`'s state machine:
   the pending re-keyed DB swaps into place *only after* the new wraps are
   committed, keyed to a persisted phase marker so a crash resumes deterministically.
   Stamp a fresh anti-rollback generation token (`db.rs::reconcile_db_generation`,
   `restore_applied`-style path) on apply.
5. On success: publish new session DEK, `zero_and_remove` the pre-rotation `.bak`,
   write a `config_audit` row (new action `dek_rotated`) + an `auth_audit` event.

**Crash-safety.** Model it as the restore machine plus one extra invariant: the
main-DB swap is the *last* destructive step and is gated on "new wraps
committed." Windows: (a) pending built, wraps not yet written → discard pending
on next launch (old DEK still valid); (b) wraps written, main not yet swapped →
detectable because new-DEK opens the pending but not the live DB → complete the
swap; (c) after swap → done. A persisted marker (`tahlk.db.rekey-phase`)
disambiguates (b) from a stale pending.

**Test plan.** Unit-test the AMK migration (AMK == `derive_audio_key(dek)`), the
wrap/unwrap round-trip for `audio_master`, and each rotation phase against
tempfile SQLCipher DBs (old DEK → staged new-DEK copy opens; wraps re-derive; the
phase state machine resumes from each window). Manual: rotate on a populated
install, confirm notes + audio still open and old recovery codes stop working.

**Environment requirement.** Validate the full apply-at-launch path on a running
build. **Exit criteria:** rotate on a real install with audio; all records +
audio open under the new password; old DEK/recovery codes rejected; a fresh
generation token present.

---

## G2 — Derive the sign-off hash server-side (finding #7) — ✅ SHIPPED (PR #95)

Shipped as designed: `crypto::sign_content_hash` + `encounters::derive_sign_hash`,
gated by a golden test that pins byte-exactness against the real JS
`computeNoteHash` (`assets/sign_hash_goldens.json`). The section below is the
original plan, kept for reference.

**Goal.** Stop trusting a client-supplied `signed_hash`; have Rust derive (or at
minimum independently recompute) it from the content it already stores.

**Why it was deferred.** Rust must reproduce the JS canonicalization
**byte-for-byte**; a mismatch rejects *every* legitimate sign-off. Not shippable
without validating against a running build.

### Design

Target JS (`src/utils/contentHash.js::computeNoteHash`):

```js
sha256Hex(JSON.stringify({ encounterId, signedBy, transcript, noteContent }))
```

Note: **fixed insertion order** (not sorted), `JSON.stringify` escaping, values
default to `''`. Inputs Rust already has: `transcript` = KV
`note_content_v1::transcript::<id>`, `noteContent` = KV `note_content_v1::<id>`,
`signedBy` = the provider name (server-derived via `kv_ops::provider_id`),
`encounterId`.

Implementation:

1. Add `notes::canonical_sign_payload(...)` building the JSON with a
   `#[derive(Serialize)]` struct whose fields are declared in the exact order
   `encounterId, signedBy, transcript, noteContent`. `serde_json::to_string`
   matches `JSON.stringify` for this shape **except** non-ASCII and a few control
   chars — pin this with a differential test (below) before relying on it.
2. At sign time (`mark_signed` path), read the two KV values on the scoped
   connection, recompute the hash, and **derive** the stored `signed_hash` from
   it (preferred) — or reject if the client value disagrees.
3. Keep the JS computation for the optimistic UI, but the value Rust persists is
   the Rust-derived one.

**The critical test (gates everything).** A cross-language golden test: a table
of inputs (ASCII, embedded quotes/backslashes/newlines, unicode incl.
astral/emoji, empty fields) hashed by *both* Node (`computeNoteHash`) and the
Rust function; assert identical digests. Ship only when this passes for every
row. If serde's escaping diverges on some input class, canonicalize explicitly
(e.g. escape to match) rather than relying on the default.

**Environment requirement.** Node + Rust toolchain to run the differential test.
**Exit criteria:** golden test green across all input classes; signing a note
still succeeds end-to-end on a running build; a hand-tampered KV content value
makes the server-derived hash differ (detectable).

---

## H2 — Bind `wrap_type` as AAD in the DEK wraps (finding #13) — ✅ SHIPPED (PR #94)

Shipped as designed: `wrap_dek`/`unwrap_dek` take `wrap_type` and bind it as AAD;
`unwrap_dek` tries the bound AAD then falls back to empty for pre-#13 wraps
(clone-before-retry). Tested incl. the legacy-wrap-still-unlocks path. The
opportunistic on-unlock re-seal was left out (credential changes already re-wrap;
the fallback handles legacy indefinitely). The section below is the original plan.

**Goal.** Bind each wrap to its role so a ciphertext can't be moved between rows;
today `wrap_dek`/`unwrap_dek` use `Aad::empty()`.

**Why it was deferred.** Existing wraps were sealed with empty AAD. Switching
`unwrap` to require AAD breaks every installed wrap → no one unlocks. Pure
defense-in-depth (not exploitable today, since all four rows wrap the identical
DEK), so it wasn't worth the blind-ship risk.

### Design (backward-compatible)

1. Thread `wrap_type: &str` into `wrap_dek`/`unwrap_dek`.
2. `wrap_dek`: seal **new** wraps with `Aad::from(wrap_type.as_bytes())`.
3. `unwrap_dek`: try `Aad::from(wrap_type)`; on auth failure, **retry with
   `Aad::empty()`** (legacy). `open_in_place` mutates its buffer, so **clone the
   ciphertext before the first attempt** and retry on the clone.
4. Opportunistic upgrade: whenever a legacy (empty-AAD) wrap successfully unwraps,
   re-seal it with AAD in the same transaction, so installs converge to
   AAD-bound wraps over normal use (`change_password`, recovery regen already
   re-wrap).
5. Update the ~15 in-file test call sites to pass a `wrap_type`.

**Migration.** No explicit migration; the try-then-fallback + opportunistic
re-seal is self-healing. Consider a one-shot "re-wrap all rows" on the next
`change_password` to converge faster.

**Test plan.** Round-trip with AAD; a wrap sealed for `recovery_1` fails to
unwrap as `password` (the property being added); a legacy empty-AAD wrap still
unwraps and is transparently upgraded; the clone-before-retry doesn't corrupt on
the fallback path.

**Environment requirement.** CI-testable (unit tests only) — this one does **not**
need a running app, just the toolchain to compile. It was deferred only to keep
it off the same PR as riskier work; it can go in as soon as someone can run
`cargo test`. **Exit criteria:** new+legacy wraps both unlock; cross-row unwrap
rejected; upgrade path covered.

---

## H3 — Argon2id for the password wrap (finding #9)

**Goal.** Replace PBKDF2-HMAC-SHA256 (210k) with a memory-hard KDF for the
password KEK, so the offline attack surface on the plaintext wraps DB is harder.

**Why it was deferred.** `argon2` is **not** in the dependency tree, so it needs
`cargo add argon2` + transitive-dep lock resolution — impossible without the
toolchain (unlike `zeroize`, which was already vendored). It also needs a
KDF-version marker + dual-path unlock so existing PBKDF2 wraps still open.

### Design

1. `cargo add argon2` (pulls `blake2`, `password-hash`); commit the regenerated
   `Cargo.lock`.
2. **Version the wrap.** `auth_dek_wraps` currently has `salt_hex`. Add a `kdf`
   column (`TEXT NOT NULL DEFAULT 'pbkdf2-sha256-210000'`) via idempotent
   `ALTER TABLE ADD COLUMN`; new password wraps write `'argon2id-<params>'`.
   Pin params explicitly (e.g. `m=19456 KiB, t=2, p=1`, i.e. OWASP's Argon2id
   baseline) inside the `kdf` string so a future tuning is self-describing.
3. `derive_kek`: dispatch on the stored `kdf` — legacy rows keep PBKDF2, new rows
   use Argon2id. `unlock_with_password` reads `kdf` alongside `salt_hex`.
4. **Migrate on unlock:** after a successful PBKDF2 unlock, re-derive the KEK with
   Argon2id and re-wrap the password row in the same transaction, so installs
   upgrade the first time each user signs in. `change_password`/recovery-reset
   write Argon2id from the start.
5. Recovery wraps stay HKDF (their 120-bit seed doesn't need stretching) — scope
   this to the *password* wrap only.

**Migration / crash-safety.** The `kdf` column defaults keep old rows valid; the
on-unlock re-wrap is a single transactional `UPDATE` — a crash before commit just
leaves the PBKDF2 row (still openable) and retries next unlock.

**Test plan.** Derive/verify round-trip for Argon2id; a legacy PBKDF2 row unlocks
and is upgraded to Argon2id (assert `kdf` flips and the DEK is unchanged); a
row's `kdf` string round-trips its params; wrong password still rejected under
both KDFs.

**Environment requirement.** Toolchain to add + lock the crate and run tests.
**Exit criteria:** fresh install uses Argon2id; an install created under PBKDF2
unlocks and self-upgrades; `Cargo.lock` committed; CI green.

---

## Tier-4 performance nits (low value, do when nearby)

The perf reviewer rated these low — they matter only for the in-memory server
fallback or are negligible today. Listed for completeness.

1. **`server/src/store.rs::InMemoryStore::list`** full-resorts per cache miss, and
   `put_encounter` bumps the tenant cache version on every status change.
   *Fix:* keep a `BTreeMap<(created_at, id), Encounter>` per tenant so `list` is
   an O(limit) walk. Only bites when the in-memory store (not Postgres) is the
   running backend.
2. **`server/src/cache.rs::InMemoryCache`** has no reaper; version-bumped/expired
   entries accumulate forever (slow leak over weeks of uptime). *Fix:* a periodic
   sweep, or swap to `moka` for the in-memory case.
3. **`audit_mac.rs`** re-derives the MAC key via HKDF on every append. *Fix:*
   cache the derived `hmac::Key` for the unlock session (invalidate on lock).
   Sub-microsecond today; only cheap-to-fix hygiene.
4. **Migration scans re-run every launch un-gated** (`destruction_log.rs`'s
   `GLOB`-filtered full scan, the `note_audit`/`note_history` KV-prefix scans).
   *Fix:* gate behind a `PRAGMA user_version` bump or a `kv` flag set only after a
   successful migration. Low value (negligible I/O today) and carries migration-
   correctness risk, so only with careful tests.
5. **`#11` (audio sweep) off the blocking path** — the O(n)-query cost is already
   fixed (#90); moving the whole sweep to a post-window spawn is the remaining
   secondary optimization. Startup-ordering change; do only with care.

**Environment requirement.** #1/#2 want a running server to profile; #3/#4/#5 are
CI-testable but low priority.
