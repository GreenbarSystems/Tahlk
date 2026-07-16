# ADR 0001 — Freeze tahlk-sync and the Group/Solo seam; focus on Solo

- **Status:** Accepted — 2026-06-29
- **Deciders:** product owner + engineering

## Context

A rapid build-out added, ahead of validated demand:

- **`tahlk-sync`** — a multi-tenant Group-tier backend (in-memory store; Postgres
  migrations written but unwired; JWT stubbed; no sync client on the desktop).
- A **Solo/Group split seam** in the desktop app — a build guard forbidding
  imports from a (nonexistent) `src/group/`, plus a capability seam.

A tech-lead review found:

- The product's real risks are **compliance** (BYOK ships PHI to Anthropic with
  no BAA) and **missing test coverage of the sign-off / hash-chain money path** —
  not a missing backend.
- The drafted sync model (**last-writer-wins**) is **unsafe for a legal audit
  chain**: you cannot LWW a signed attestation, and the per-device SHA-256 chain
  forks under multi-device editing. Sync needs a real design before any code.
- There is **no validated demand** for the Group tier yet.

Continuing to invest here spreads a small team across unvalidated surface area
and creates a second source of truth for the encounter schema (desktop `lib.rs`
vs server `model.rs`, already diverging: `audio_path` vs `audio_object_key`).

## Decision

Freeze all future development of `tahlk-sync` and the Group/Solo seam. Focus
exclusively on finishing the single-user **Solo** desktop product.

"Frozen" means:

- No new features or changes to `server/`; no new `src/group/` modules and no
  extensions to the capability / build-guard seam.
- Frozen code **stays in CI** so it keeps compiling (anti-rot insurance). It is
  **not deleted** — the design and migrations remain as a reference for when
  sync is real.
- Capability accessors that are **load-bearing today** (`currentProvider` /
  `currentUser` → audit actor identity) remain; they are not part of the freeze.

## Unfreeze criteria (all required)

1. A signed Group/Enterprise pilot or customer with a concrete multi-provider /
   multi-device requirement.
2. An **audit-safe sync design** on paper: append-only per-device hash chains
   with server-side merge — never last-writer-wins for signed/attested state.
3. **Security findings S1 and S2** — originally numbered against
   `tahlk-security-audit.md`, a source document that was never committed to
   this repository or its git history; the current authoritative record of
   these findings is
   [`docs/security/hipaa-risk-assessment.md`](../security/hipaa-risk-assessment.md) —
   are remediated: real JWT verification (S1) and body-size limit + rate limiting
   + fail-closed bind gate (S2) landed in `server/`. These are today's Critical
   items **on any deploy**; unfreezing the service without them shipping is
   how tenant-isolation breaks in prod. Track in
   [`docs/security/pre-deploy-checklist.md`](../security/pre-deploy-checklist.md).

   > **Note (2026-07-05):** the S1/S2 code fix has landed as a scoped,
   > security-only exception to this freeze (permitted precisely because this
   > criterion calls for it). This satisfies criterion #3 only. The service
   > **remains frozen** — criteria #1 (signed Group pilot) and #2 (audit-safe
   > sync design) are still unmet — and no new Group-tier features, endpoints,
   > or seam expansion were added. This ADR's Status stays **Accepted /
   > frozen**.
   >
   > **Note (2026-07-05):** the S3 (redacted structured error logging) and S4
   > (swap-in `RedisCache`) fixes have since landed under the *same* scoped
   > security/correctness-only exception, extending the S1/S2 precedent. These
   > are hardening of existing cache/error-handling code — no new Group-tier
   > features, endpoints, or seam expansion. The service **remains frozen** for
   > the unmet criteria #1 and #2; this ADR's Status stays **Accepted / frozen**.

## Consequences

- Solo is the single focus. The finishing work (see review): sign-off /
  hash-chain integration tests, committed lockfile, OS-keychain for the API key,
  the compliance path (BAA + managed key), signed installer + whisper DLL
  bundling, and finishing **or** reverting the in-progress UI migration.
- Multi-device sync and desktop/server schema convergence are explicitly
  deferred, with the constraints above recorded so we don't paint into a corner.
