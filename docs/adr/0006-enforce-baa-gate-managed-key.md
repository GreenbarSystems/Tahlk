# ADR 0006 — Enforce the BAA/EULA acknowledgment gate under the managed-key proxy

- **Status:** Accepted — 2026-07-23
- **Deciders:** product owner + engineering
- **Supersedes:** [ADR 0003](0003-disable-baa-gate-for-beta.md) (BAA gate soft-disabled for the test-data-only beta)
- **Related:** ADR 0004 (first-open authentication); `MANAGED-KEY-ROLLOUT.md`; `docs/security/hipaa-risk-assessment.md` Flow D

## Context

ADR 0003 soft-disabled the BAA acknowledgment gate (`baa::GATE_ENABLED = false`)
for a beta cohort using synthetic/test data only, and removed the BAA step from
onboarding. It named two unfreeze criteria; the first — **the managed-key proxy
ships** — has now been met:

- BYOK is fully retired. The desktop app holds no Anthropic key of its own. It
  registers a per-device identity transparently and routes every note-generation
  call through Greenbar's server-side proxy, which uses Greenbar's own
  ZDR-covered Anthropic key (see `notes.rs`, `device.rs`, `MANAGED-KEY-ROLLOUT.md`).
- The compliance model is settled: Greenbar Systems is the practice's **business
  associate**; Anthropic is Greenbar's subcontractor under ZDR. The provider
  accepts a **BAA + EULA with Greenbar**, not a BAA with Anthropic. There is no
  longer any user-owned Anthropic account to vouch for — the ADR 0003 framing
  ("the Anthropic account behind their API key is covered") no longer describes
  anything that exists.

With real PHI now flowing through the managed proxy, the "no technical control"
risk that ADR 0003 accepted for the beta is no longer acceptable. The gate must
be enforced, and — critically — onboarding must collect the acknowledgment,
because an enabled gate with no onboarding path produces an opaque `BaaRequired`
error on a new user's very first note generation (the H2 audit finding this ADR
closes).

## Decision

1. **`baa::GATE_ENABLED = true`.** `require_ack` returns `AppError::BaaRequired`
   whenever the ack row is missing or stale, before any network I/O in
   `notes::generate_note`. A compromised WebView cannot bypass it. The
   `resolve_ack(stored, gate_enabled)` split and its disabled-branch unit tests
   are retained as a single-flag kill switch, but production runs enabled.

2. **Onboarding blocks on BAA/EULA acknowledgment.** `src/solo/onboarding.js`
   gains a second step: an accurate summary of the Greenbar BAA/EULA relationship
   and a checkbox that must be explicitly checked before onboarding completes.
   The acknowledgment is recorded through the same `baaRepo.setAck` →
   `baa_ack_set` command the Settings pane uses, so there is one source of truth
   for "has this been acknowledged." Onboarding is not marked complete if the ack
   write fails. A fresh install that finishes onboarding can therefore generate a
   note immediately, without hitting `BaaRequired`.

3. **Settings becomes a re-confirm / status surface.** The Settings BAA section
   keeps its checkbox (re-confirm / revoke) but its copy is corrected to describe
   Greenbar's proxy-mediated, ZDR-covered processing rather than a user-owned
   Anthropic account, and drops all "optional / beta / test data only" framing.

4. **Doc and comment drift is cleaned up** across `baa.rs`, `notes.rs`,
   `src/data/baa.js`, and `settingsModal.js`, all of which previously described
   the gate as disabled/non-blocking.

## Consequences

- A new install cannot generate a note without accepting the BAA/EULA — the
  compliance posture now matches the code, and the first-note path no longer
  surfaces an unexplained error.
- Revoking the acknowledgment in Settings immediately blocks further note
  generation (the Rust gate re-checks on every call), which is the intended
  behavior for a provider who needs to re-attest after a BAA renegotiation.
- `ATTESTATION_VERSION` remains the mechanism for forcing re-acceptance after
  material BAA/EULA changes; bumping it invalidates existing acks and routes
  users back through acknowledgment (onboarding for fresh installs, the Settings
  toggle for existing ones).

## Notes on scope

This ADR does not change the attestation storage schema, the `AppError::BaaRequired`
wire shape, or `ATTESTATION_VERSION` (still `1`). It only flips enforcement on,
adds the onboarding step, and corrects copy/comments. ADR 0004 (first-open
authentication) is a separate, still-proposed control and is unaffected.
