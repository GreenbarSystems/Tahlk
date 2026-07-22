# ADR 0003 — Disable the BAA acknowledgment gate for the test-data-only beta

- **Status:** **Superseded — 2026-07-21.** `baa::GATE_ENABLED` is `true` and
  the onboarding step is restored. See "Supersession" at the foot of this file.
- **Originally:** Accepted — 2026-07-06
- **Deciders:** product owner + engineering

## Context

Tahlk's compliance posture (audit finding C2) requires a provider to
affirmatively acknowledge that the Anthropic account behind their API key is
covered by an executed Business Associate Agreement before `generate_note`
will transmit a transcript. This is enforced twice: an onboarding step 3
checkbox (JS UX) and a Rust-side choke point, `baa::require_ack`, called
before any network I/O in `notes.rs` — a WebView compromise cannot bypass it.

The current beta cohort is explicitly using **synthetic/test data, not real
patient information**, until Tahlk ships a managed Anthropic key with an
org-level BAA covering every provider (so individual practices no longer need
their own BYOK BAA). Until that ships, every BYOK provider still needs an
Anthropic account and their own BAA if they were sending real PHI — but this
beta cohort isn't, so the gate is pure onboarding friction with zero
compliance benefit for the data actually in flight right now.

> **Model clarification (2026-07-17, does not change this decision):** the
> compliance model has since been defined as **managed-key**: the provider's
> BAA and a EULA are with **Greenbar Systems** (Greenbar is the Business
> Associate; Anthropic is Greenbar's subcontractor), not the provider directly
> with Anthropic — see `MANAGED-KEY-ROLLOUT.md` and
> `docs/security/hipaa-risk-assessment.md` Flow D. This ADR's decision (make the
> gate non-blocking for the test-data-only beta) is unchanged; only read the
> "provider's own BAA with Anthropic" framing above as the transitional BYOK
> mechanism, not the target model. The confirmation the gate records is now the
> provider's acceptance of Greenbar's BAA + EULA.

## Decision

Soft-disable the gate rather than delete it.

- `src-tauri/src/baa.rs`: added `GATE_ENABLED: bool = false`, a single
  choke-point flag. `require_ack` now routes through a pure `resolve_ack(stored,
  gate_enabled)` function: when disabled, a missing ack no longer errors, but
  an *existing* ack (a tester who already has their own BAA and voluntarily
  recorded it in Settings) is still honored and still attributed correctly in
  the `llm_audit` table. Both branches are unit-tested so re-enabling later is
  a one-line, test-covered change.
- `src/solo/onboarding.js`: removed step 3 (the BAA checkbox, its help
  disclosure, and the `baaChecked` gate in `wireOnboarding`) and the `baaRepo`
  import. Onboarding is now 2 steps: provider profile, then API key.
- `src/solo/settingsModal.js`: the BAA acknowledgment section is **kept**
  (storage, toggle, `baaRepo.getStatus/setAck/clear` all still work) but its
  copy was corrected — it no longer claims note generation is blocked without
  it, and now frames the checkbox as optional/voluntary for any tester whose
  org already has a real BAA and wants the local audit trail.

What was deliberately **not** touched: `baa.rs` storage, its existing tests,
`src/data/baa.js`, `AppError::BaaRequired` and its `userMessage` copy, or
`test_baa.mjs` (which tests the JS↔Rust contract for that error code
independent of whether Rust currently emits it). All of this stays intact so
the gate is a flag flip away from fully back on, not a rebuild.

## Consequences

- New installs during the beta are not blocked on a BAA attestation they
  don't yet need for the data they're actually using.
- If a beta tester pastes real PHI despite the test-data-only instruction,
  there is currently **no technical control** stopping that transcript from
  reaching Anthropic via their own BYOK key. This is a known, accepted risk
  for the duration of the beta — mitigated by product/process (test-data-only
  guidance), not by code, until the criteria below are met.
- `docs/RELEASE.md` / `SETUP.md` / `GETTING_STARTED.md` were updated to
  describe the gate as currently non-blocking, pointing here for why.

## Unfreeze / re-enable criteria (either one)

1. **The managed-key proxy ships** — Tahlk holds the API key and an
   org-level BAA server-side; individual providers no longer need their own
   BYOK BAA at all, and the onboarding/Settings flow should be redesigned
   around that (not simply re-adding step 3 as it was).
2. **Beta scope changes to include real PHI before #1 ships** — flip
   `GATE_ENABLED` back to `true` and restore the onboarding step immediately;
   do not wait for the managed key in that scenario.

## Status update — 2026-07-18

Progress on the compliance prerequisites that gate re-enabling this flag,
recorded here so this ADR reflects the same real-world status as
`docs/security/hipaa-risk-assessment.md` §2 Flow D:

- **Greenbar ↔ Anthropic BAA: executed 2026-07-18.** ZDR provisioning on the
  dedicated Anthropic organization behind the future managed-key proxy is
  pending Anthropic approval. Real-PHI use through the managed proxy is
  blocked on ZDR provisioning, not on the BAA itself.
- **Provider ↔ Greenbar BAA + EULA: in attorney drafting, week of
  2026-07-13.** A licensed healthcare attorney is drafting both agreements.
  Neither is finalized or executed with any practice yet.

Neither change flips `GATE_ENABLED` on its own. Criterion #1 above still
requires the managed-key proxy to ship; criterion #2 still requires an
explicit scope change. This ADR remains in force until one of those two
conditions is met.

## Supersession — 2026-07-21

`GATE_ENABLED` is now `true` and onboarding collects the attestation again.
This ADR is superseded.

**Note that neither unfreeze criterion above was met.** The managed-key proxy
has not shipped, and beta scope has not formally expanded to real PHI. The gate
was re-enabled on a different basis: a privacy code audit ranked the disabled
gate as its highest-priority finding, and with the app moving toward real
patient data the fail-closed posture was judged correct ahead of the criteria
rather than because of them. Turning it on costs usability; leaving it off
risks uncovered PHI egress. That trade was resolved in favour of the records.

**What went wrong in between, recorded because it is the useful part.** The
flag was flipped on 2026-07-21 (`a191edc`) WITHOUT the onboarding step this
ADR explicitly required — "flip `GATE_ENABLED` back to `true` **and restore the
onboarding step** immediately". The result: every new install completed setup,
hit `baa_required` on its first Generate, and was directed to a Settings pane
whose own copy called the confirmation "optional". The app was unusable for
new users for the intervening period, and five documents plus a test still
asserted the flag was `false`.

The lesson is not "read the ADR" — it is that a flag with a documented
companion change needs the companion enforced in code, not prose.
`baa::the_gate_is_enabled_in_shipped_builds` now pins the constant, and
`test_onboarding.mjs` pins the step and its copy. A future flip in either
direction has to change a test that says why.

**Still true from the original decision:** the gate being enforced does not
make real-PHI use supported. ZDR provisioning on the Anthropic organisation is
still pending, and the provider↔Greenbar BAA and EULA are still unexecuted. The
gate ensures no transcript leaves the device without a recorded attestation; it
does not make the downstream path covered. Those remain tracked in
`MANAGED-KEY-ROLLOUT.md` and `docs/security/hipaa-risk-assessment.md` Flow D.

**Attestation copy is provisional.** The onboarding and Settings text names the
BAA and EULA in general terms because neither document is executed yet. When
they are, replace the copy with wording that matches them and bump
`baa::ATTESTATION_VERSION` (and `BAA_ATTESTATION_VERSION` in `src/data/baa.js`,
which `test_baa.mjs` now checks for drift) so every provider re-confirms
against the final text.
