# State Consumer Health Data Laws — Scope Determination (WA MHMDA, NV SB370, CT)

**Status:** Draft — internal working determination, pending legal/compliance review and sign-off. **Not a substitute for counsel's advice.** Nothing here is a legal opinion; the applicability thresholds below must be confirmed by counsel licensed in each state.

**Date:** July 25, 2026

**Author:** Prepared by Claude Code (AI agent) at Ryan Moore's direction, based on the July 2026 state health-law compliance review of the Tahlk codebase (finding **S2**).

## Purpose

Record Greenbar Systems' current determination of whether the new wave of **state consumer-health-data privacy laws** applies to Tahlk, and under what conditions that determination must be revisited. These laws are distinct from HIPAA and, in Washington's case, carry a **private right of action**.

## The laws in scope

- **Washington My Health My Data Act (MHMDA)** — regulates "consumer health data" (CHD) collected about WA consumers. Requires a **separate CHD privacy policy** posted **before** collection, **opt-in consent to collect**, a **distinct consent to share**, and a valid **authorization to sell**. Enforceable under the WA Consumer Protection Act, including a **private right of action**.
- **Nevada SB370** — a consumer-health-data law broadly parallel to MHMDA (consent + privacy policy), enforced by the state AG (no private right of action).
- **Connecticut (CTDPA health-data amendments)** — adds "consumer health data" protections to Connecticut's comprehensive privacy act, including consent for processing sensitive/health data.

"Consumer health data" in these statutes is defined broadly and **squarely includes mental- and behavioral-health information** — the most sensitive category Tahlk handles.

## How Tahlk touches consumer health data

- Tahlk collects and stores behavioral-health encounter audio, transcripts, and clinical notes on the device.
- It **shares** transcript content with Anthropic (via Greenbar's managed proxy) to generate notes — a "share" under MHMDA's definition.
- As of this review, Tahlk has **no** CHD-specific privacy policy and **no** consumer consent flow (`MANAGED-KEY-ROLLOUT.md` lists a privacy policy as an unchecked TODO).

## The HIPAA / covered-entity exemption (the pivotal question)

MHMDA and its siblings **exempt PHI that is handled by a HIPAA covered entity or business associate** consistent with HIPAA. Much of the clinical data in Tahlk is PHI created/maintained by the provider (a covered entity), which **may** place it within that exemption. **But the exemption is not automatic or total:**

1. It turns on the data being handled **as HIPAA PHI by a covered entity / BA** — which depends on the executed BAA chain that finding **C1** shows is not yet complete.
2. Data Tahlk collects **outside** the covered-entity treatment context (e.g., consumer-facing marketing data, device analytics, or any direct-to-consumer surface) is **not** automatically exempt.
3. Some obligations (e.g., a posted privacy policy describing collection/sharing) are cheap to satisfy and reduce risk even where an exemption is arguable.

## Current determination

**A definitive determination requires counsel and is not yet made.** Working position:

- For clinical PHI handled under a complete HIPAA covered-entity/BA chain, the HIPAA exemption is **likely** to apply — **contingent on C1** (executed provider↔Greenbar BAA + Greenbar↔Anthropic ZDR). Until C1 closes, do **not** rely on the exemption for real-PHI traffic.
- Independent of the exemption analysis, Tahlk should ship a **plain-language privacy notice** (finding **S7**) describing what is collected, that transcripts are shared with a ZDR subcontractor to generate notes, and that data is not sold or used for training. This is low-cost and defensible under all three statutes.

## Conditions that would trigger (or harden) applicability

Revisit immediately if any occur:
1. Tahlk adds any **direct-to-consumer** or patient-facing surface (patient app, portal, intake) that collects health data outside the provider's covered-entity context.
2. Tahlk collects device/usage analytics that could be "consumer health data" (e.g., inferences about a user's health).
3. The C1 BAA/ZDR chain is **not** completed but real-PHI traffic begins — the HIPAA exemption cannot be leaned on, so MHMDA's consent + policy obligations attach directly.
4. Counsel advises the exemption is narrower than assumed, or a new state (e.g., additional 2026 CHD statutes) is added to this list.

## Action items

1. **Engage counsel** for a definitive MHMDA/NV/CT applicability opinion, keyed to the states where Tahlk providers actually practice (now capturable via the provider's practice state).
2. **Ship a patient-facing privacy notice** (S7) regardless of the exemption outcome.
3. **Do not send real-PHI beta invitations** to WA/NV/CT providers until (1) is resolved and **C1** is closed — the same operational hold C1 already imposes.
4. Keep this determination synchronized with the C1 status in `docs/security/hipaa-risk-assessment.md` §2 Flow D.

## Sign-off

- [ ] Reviewed by: _________________ (legal/compliance)
- [ ] Date: _________________
- [ ] Approved as final determination / Revised (attach redline)
