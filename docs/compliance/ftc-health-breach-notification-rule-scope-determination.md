# FTC Health Breach Notification Rule — Scope Determination

**Status:** Draft — internal working determination, pending legal/compliance review and sign-off. Not a substitute for counsel's advice.

**Date:** July 23, 2026

**Author:** Prepared by Computer (AI agent) at Ryan Moore's direction, based on the July 22, 2026 HIPAA compliance audit of the Tahlk codebase.

## Purpose

This document records Greenbar Systems' current determination of whether the FTC Health Breach Notification Rule (as amended in 2024, broadening the definition of a "personal health record" (PHR) vendor) applies to Tahlk.

## Background

The FTC's rule requires vendors of personal health records — and related entities — to notify affected individuals, the FTC, and in some cases the media, following a breach of unsecured, individually identifiable health information. The 2024 amendment broadened the PHR-vendor definition, expanding the range of health apps and platforms potentially in scope beyond its original, narrower reading.

## Current product model

Tahlk is a clinician-controlled ambient scribe: the software is operated by the healthcare provider (podiatrist, behavioral health clinician, etc.) to draft and manage clinical notes. Patients do not sign up for, log into, or directly control any Tahlk account or interface. There is no patient-facing app, portal, or PHR feature of any kind in the current product.

## Determination

**Current determination: the FTC Health Breach Notification Rule does not apply to Tahlk in its current form.**

Rationale:
- The rule targets entities offering personal health records "drawn from multiple sources" and controlled by the individual consumer/patient, or vendors/service providers to such PHR products.
- Tahlk has no patient-facing surface. All access is clinician-controlled; patients have no account, login, or direct interaction with the software.
- Tahlk does not aggregate health data across multiple unrelated sources for patient-directed control — it is a single-practice clinical documentation tool.

## Conditions that would trigger re-determination

This determination must be revisited if any of the following occur:
1. Any patient-facing feature is added — e.g., a patient portal, patient-accessible note-sharing, an app or web view a patient logs into directly.
2. Tahlk begins aggregating data across multiple unrelated provider sources into a patient-controlled view.
3. The product model shifts from purely clinician-controlled to any form of patient-initiated account or data control.
4. Legal counsel advises the amended rule's broadened definition captures Tahlk's current architecture despite the above (this is a genuinely broadened rule as of 2024, and interpretations continue to develop — this determination should be revisited periodically even absent a product change).

## Sign-off

- [ ] Reviewed by: _________________ (legal/compliance)
- [ ] Date: _________________
- [ ] Approved as final determination / Revised (attach redline)
