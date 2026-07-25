# ADR 0008 — Encrypted backup export

- **Status:** Accepted — 2026-07-25
- **Deciders:** product owner + engineering
- **Related:** open-item OPS-3; `docs/security/hipaa-risk-assessment.md` §5 (contingency plan)

## Context

Tahlk Solo keeps the entire patient record in a single SQLCipher database on one
device, with no Tahlk-operated backend and no built-in backup. If the device or
the encryption key is lost, there is no in-app recovery — every record on that
device is gone. HIPAA §164.308(a)(7) (contingency plan) expects a data-backup
plan; until now the risk assessment could only put that responsibility entirely
on the practice, with no tooling. Open-item OPS-3.

## Decision

Ship an in-app **encrypted backup export** in Settings.

- **Format: a single, self-contained SQLCipher database**, produced with
  `sqlcipher_export` into a destination `ATTACH`ed under a **provider-chosen
  backup passphrase** (SQLCipher's default PBKDF2 KDF). This is the same
  primitive `db.rs` already uses for its plaintext→encrypted migration, keyed by
  a passphrase instead of the raw DEK.
- **The backup is recoverable with just the passphrase** — independent of the
  device's DEK, its OS keychain, and the `auth_dek_wraps` file. That is the
  point: a backup that could only be opened with artifacts stored *on the lost
  device* would be worthless.
- **The passphrase is separate from the login password.** It is validated to the
  same ≥12-character floor, entered with a confirm field (a typo would key an
  unrecoverable backup), never logged, and errors never echo the ATTACH/KEY SQL
  (which carries it). The provider is told plainly that Tahlk cannot recover the
  passphrase.
- **Provider-directed egress.** The file is written only to a location the
  provider picks via the native Save-As dialog, and the command refuses to write
  over the live `tahlk.db` / `tahlk_auth.db`. Unlike the note exports, the file
  is encrypted, so it is not the same accepted-plaintext-residual as Flow C.
- **Audited as metadata.** A metadata-only log line records that a full-record
  backup was produced (no PHI — the file is ciphertext), as §164.308(a)(7)
  evidence.

## Scope: export now, restore later

This ADR ships **export only**. Restoring a backup into an install is a larger,
separate flow — it must import the data into the target install's database and
re-wrap the DEK under that install's password (the target has its own DEK/auth
state). The exported file is a standard SQLCipher database, so it is recoverable
with the passphrase using SQLCipher tooling in the interim; an in-app restore is
tracked as the OPS-3 follow-up.

## Consequences

- The §164.308(a)(7) data-backup gap moves from "entirely the practice's
  problem, no tooling" to "one-click encrypted export"; the practice still owns
  where the file is stored and testing that it restores.
- Recoverability now depends on the provider remembering the backup passphrase —
  named explicitly in the UI copy and in §5.
- Rejected: **copying the raw DB file + the wraps** (recoverable only with the
  device's password *and* the wraps file, and a two-file bundle); and
  **re-keying with the DEK** (`VACUUM INTO` same-key — the backup would then need
  the raw DEK, which no human knows, to restore).
