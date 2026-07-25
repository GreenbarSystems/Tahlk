# ADR 0009 — Backup restore flow (staged, records-only)

- **Status:** Accepted — 2026-07-25
- **Deciders:** product owner + engineering
- **Related:** [ADR 0008](0008-encrypted-backup-export.md) (export); open-item OPS-3; `docs/security/hipaa-risk-assessment.md` §5

## Context

ADR 0008 shipped an encrypted backup **export**. The other half of a contingency
plan (§164.308(a)(7)) is **restore** — getting a backup's records back onto an
install after a lost/failed device or an accidental deletion. Restore is the
most consequential operation in the app: it **replaces the live database**.

Two facts shape the design:

1. **Keying mismatch.** The backup is encrypted under the *backup passphrase*
   (PBKDF2). The live DB is keyed under the install's *DEK* (raw key), which the
   login password unwraps via `auth_dek_wraps`. Dropping the backup file in as
   `tahlk.db` would leave it keyed under the passphrase, and the login password
   could no longer open it.
2. **The pool holds the live DB open.** Swapping the file while the connection
   pool is live is unsafe, and this cannot be runtime-tested in the dev
   environment.

## Decision

### Re-key into the install's DEK

Restore **re-keys the backup's contents into this install's DEK** (the inverse
of export), via `sqlcipher_export` from the passphrase-keyed backup into a file
`ATTACH`ed under the DEK. The install's existing login password / wraps keep
working — the user does not set a new password.

### Two-phase: stage now, swap on next launch

- **Stage (a Settings command, non-destructive).** `stage_backup_restore` opens
  the chosen backup with the passphrase, re-keys it into a **pending file**
  (`tahlk.db.restore-pending`) keyed with the DEK, and verifies that file opens.
  It **never touches the live DB or the pool** — a mistake or crash here cannot
  corrupt current data.
- **Swap (at open time, before the pool exists).** `apply_pending_restore` runs
  inside `open_database_with_dek`, after migration recovery and before the pool
  is built. It uses the **same rename-before-destroy discipline** as the
  plaintext→encrypted migration: move the current DB to `tahlk.db.pre-restore.bak`
  (a safety copy), promote the verified pending into place. It is crash-safe and
  idempotent, and it only ever swaps in a pending that **actually opens with the
  DEK** — a pending it cannot read is discarded rather than replacing good data.

This is chosen over an immediate in-session swap specifically because the
destructive step then runs at startup with no live pool, reusing proven,
crash-safe machinery — the safest shape for a feature that cannot be
runtime-tested here.

### Scope: records only

The backup — and therefore restore — covers the SQLCipher database: notes,
**transcripts (text)**, patient roster, encounters, and audit trails. It does
**not** include the raw **audio recordings** (separate encrypted files on disk
that the export never bundled). After a restore, encounters may reference audio
that is not present; the UI already handles missing audio. This limitation is
stated in the Settings copy and in §5. Bundling audio is a possible future
enhancement to both export and restore.

### Confirmation

Restore requires the backup **passphrase** and a **typed `RESTORE` confirmation**
in the UI. A `.pre-restore.bak` safety copy of the prior database is kept only
until the restored DB opens cleanly, then zeroed and removed.

### Accountability (audit finding #2)

A restore replaces the **entire** record DB — every table and every audit
trail. Because the restored copy is a legitimate prior export, its internal
hash-chains verify clean, so the chains alone cannot distinguish a normal launch
from a substitution of an older, more favourable record set. Restore is
therefore recorded on two independent surfaces, neither of which the swap itself
overwrites:

- **`restore_staged`** — written to the wraps DB (`tahlk_auth.db`) by the
  Settings command while the session is healthy and unlocked. This is the
  reliable, compliance-grade record that a provider initiated a full-record
  restore (recorded on failed attempts too). The wraps DB is not part of the
  swap, so it survives.
- **`database_restored`** — a `config_audit` row written into the **restored DB
  itself** at the next launch when the staged copy is applied, plus a
  best-effort `restore_applied` wraps-DB event. This marks the live DB an
  auditor inspects as having been installed via restore.

Detecting a *filesystem-level* substitution of `tahlk.db` (an attacker with no
DEK swapping in an older ciphertext DB out-of-band) is a separate control
tracked as anti-rollback detection; see AUDIT-RESIDUAL-RISK.md.

## Consequences

- The §164.308(a)(7) contingency plan now has both halves: export and restore,
  and a restore is durably accounted for (finding #2).
- Recovery depends on the provider remembering the backup passphrase.
- The `.pre-restore.bak` is bounded to the session in which the restore applied
  rather than retained indefinitely, so a full DEK-encrypted copy of the prior
  record set does not linger outside the retention/destruction machinery.
- Rejected: **immediate in-session swap** (destructive step runs live, untestable
  here); **replacing `tahlk_auth.db` too** (the backup has no wraps and the
  passphrase is not the login password); **restore-into-fresh-install with a new
  password** (would require re-wrapping the DEK — more moving parts than re-keying
  into the existing install's DEK).
