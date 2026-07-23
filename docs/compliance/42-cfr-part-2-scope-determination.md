# 42 CFR Part 2 Scope Determination

**Status:** Draft — internal working determination, pending legal/compliance review and sign-off. Not a substitute for counsel's advice.

**Date:** July 23, 2026

**Author:** Prepared by Computer (AI agent) at Ryan Moore's direction, based on the July 22, 2026 HIPAA compliance audit of the Tahlk codebase.

## Purpose

This document records Greenbar Systems' current determination of whether 42 CFR Part 2 ("Part 2" — the federal confidentiality regulation for substance use disorder patient records) applies to Tahlk in its current form, and under what conditions that determination would need to be revisited.

## Background

The 2024 final rule aligning Part 2 more closely with HIPAA took effect with a compliance deadline of February 16, 2026 — a deadline that has already passed as of this document's drafting. Part 2 applies to "Part 2 programs": individuals or entities that are federally assisted and that hold themselves out as providing, and provide, substance use disorder (SUD) diagnosis, treatment, or referral for treatment.

## Current product scope

Tahlk's beachhead market is podiatry, with active expansion into behavioral health and psychiatry. Its clinical note templates include `crisis-assess.json`, `psych-eval.json`, `med-mgmt.json`, and `therapy-progress.json`. These templates may capture substance use history as part of a general psychiatric or behavioral health encounter — but Tahlk does not currently market to, onboard, or serve dedicated SUD/MAT (medication-assisted treatment) programs, detox facilities, or any customer that holds itself out as specializing in SUD diagnosis or treatment.

## Determination

**Current determination: Part 2 does not apply to Tahlk's current customer base.**

Rationale:
- Part 2's threshold requirement is that the *provider organization* holds itself out as a SUD program — not merely that a clinician using Tahlk occasionally documents substance use history within a general psychiatric or primary-care encounter.
- None of Tahlk's current templates are structured as, or marketed toward, a dedicated SUD treatment record; they are general behavioral-health/psychiatric templates that may incidentally reference substance use as one clinical data point among many.
- Tahlk has no current customers identified as dedicated SUD/MAT clinics, detox programs, or similar federally-assisted SUD-specialty providers.

## Conditions that would trigger re-determination

This determination must be revisited if any of the following occur:
1. Greenbar begins actively marketing to or onboarding customers that are themselves SUD/MAT programs, detox facilities, or similarly specialized providers holding themselves out as such.
2. A dedicated "SUD program" note template or workflow is built (as opposed to general behavioral-health templates that may reference substance use incidentally).
3. Any current customer's practice model shifts such that they begin holding themselves out publicly as a SUD treatment provider.
4. Legal counsel advises that the "holds itself out" threshold is met by a lower bar than assumed here.

## Action items if re-determination becomes necessary

If Part 2 is later determined to apply to some subset of customers, Tahlk's current single-consent data model (one consent framework for all clinical data, no SUD-specific segregation or re-disclosure consent tracking) would need architectural changes before onboarding any in-scope customer — this is flagged as a known gap, not yet built, and should not be treated as "handled" simply because this document exists.

## Sign-off

- [ ] Reviewed by: _________________ (legal/compliance)
- [ ] Date: _________________
- [ ] Approved as final determination / Revised (attach redline)
