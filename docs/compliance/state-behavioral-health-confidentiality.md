# State Behavioral-Health Confidentiality — Scope Determination

**Status:** Draft — internal working determination, pending legal/compliance review and sign-off. **Not a substitute for counsel's advice.** The statutory requirements summarized here must be confirmed by counsel licensed in each state; this is not a legal opinion.

**Date:** July 25, 2026

**Author:** Prepared by Claude Code (AI agent) at Ryan Moore's direction, based on the July 2026 state health-law compliance review of the Tahlk codebase (finding **S3**).

## Purpose

Record Greenbar Systems' current determination of how **state mental-/behavioral-health confidentiality statutes** — which are frequently **stricter than HIPAA** — bear on Tahlk, in particular on the disclosure of transcript content to Anthropic (via Greenbar's managed proxy) to generate notes.

## Why this is distinct from HIPAA

HIPAA sets a floor; many states impose heightened protection specifically for **mental-health, psychotherapy, and behavioral-health records**, and HIPAA expressly defers to more protective state law. Common features:

- **Specific written patient authorization** to disclose MH records to a third party, beyond a general treatment consent or a business-associate arrangement.
- Heightened protection for **psychotherapy notes** (also a HIPAA concept, but state law often extends it).
- Narrow definitions of permissible re-disclosure.

Representative statutes (verify current text/scope with counsel):

- **California — Confidentiality of Medical Information Act (CMIA)** — heightened rules for medical information, with additional force for mental-health information; interacts with CA psychotherapist-patient privilege.
- **Illinois — Mental Health and Developmental Disabilities Confidentiality Act (MHDDCA)** — one of the strictest; generally requires **specific written consent** for disclosure of MH records, with limited exceptions.
- **New York — Mental Hygiene Law (MHL) §33.13** — governs confidentiality and release of clinical records held by MH facilities/providers.
- Analogous statutes exist in most states (e.g., MA, TX, etc.).

## How Tahlk implicates these statutes

The **disclosure of a behavioral-health transcript to Anthropic** (a third party, via Greenbar as business associate) is defended **federally** by the BAA/ZDR chain (finding **C1**). But under several of these state statutes, a business-associate agreement alone may **not** be sufficient authorization to disclose mental-health information to a third party for processing — **specific patient authorization** may be required. Tahlk's consent capture, prior to finding **S1**, recorded no patient authorization at all; S1 now captures patient **consent to record**, but not necessarily a state-form **authorization to disclose MH records to an AI subcontractor**.

## Current determination

**A definitive, state-by-state determination requires counsel and is not yet made.** Working position:

- The **S1 consent gate** is the natural place to also capture, where a provider's state requires it, the patient's **authorization to process the encounter using Greenbar's AI note-generation service (with Anthropic as a ZDR subcontractor)**. This should be added as a state-conditional element of the S1 flow rather than a separate surface.
- Until counsel confirms the per-state requirements and any required authorization language, providers in strict-consent states (at minimum IL, CA, NY) should be treated as **higher-risk** for real-PHI onboarding, alongside the existing **C1** hold.
- Psychotherapy-notes handling: confirm whether any Tahlk template or workflow produces content that qualifies as psychotherapy notes under state law, which may carry its own disclosure/segregation rules.

## Conditions that would trigger re-determination

1. Onboarding a provider in a strict-consent state (IL/CA/NY and analogs) for **real** patient data.
2. Counsel confirms a specific written-authorization requirement that the S1 attestation does not satisfy.
3. A template/workflow is identified that produces psychotherapy-notes-class content requiring separate handling.
4. The C1 BAA/ZDR chain changes the third-party-disclosure analysis (in either direction).

## Action items

1. **Engage counsel** for a per-state matrix of behavioral-health disclosure-authorization requirements, keyed to the provider practice-state field now captured at onboarding.
2. **Extend the S1 consent flow** with a state-conditional patient **authorization-to-disclose** element where required, with counsel-approved language.
3. Coordinate with the **C1** hold and the consumer-health-data determination (`state-consumer-health-data-scope-determination.md`) — the three interlock for any real-PHI go-live.
4. Confirm the psychotherapy-notes question for the shipped template set.

## Sign-off

- [ ] Reviewed by: _________________ (legal/compliance)
- [ ] Date: _________________
- [ ] Approved as final determination / Revised (attach redline)
