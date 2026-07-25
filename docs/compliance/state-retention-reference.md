# State Medical-Record Retention — Provider Reference

**Status:** Reference material for providers configuring Tahlk's retention window.
**NOT LEGAL ADVICE.** Retention statutes change and are fact-specific (record
type, patient age, licensure). Every figure below must be confirmed against
current statute and your licensing board's rules by counsel licensed in your
state. Tahlk does **not** auto-apply any figure here — you set your retention
window in Settings → Privacy & data retention, and you are responsible for
setting it to your state's requirement.

---

## Why this exists (finding S4)

Tahlk previously assumed Arizona retention law in code and captured no state at
all. It now captures your **practice state** on the provider profile and holds a
minor's record until majority + your window (`retention.rs`
`minor_extension_allows_destruction`). But the **numeric window itself** is
yours to set — this document helps you set it correctly.

## How to determine your window

For your state, look up three things and take the **longest** applicable:

1. **Adult general-medical-record floor** — a statute or health-department rule
   (often 6–10 years from last treatment).
2. **Your licensing board's rule** — psychology/psychiatry/social-work boards
   frequently impose their own, sometimes longer, retention period.
3. **Minor records** — nearly all states require holding a minor's record past
   the age of majority; the tail varies (until 18, 21, or a fixed number of
   years after majority). Tahlk models "majority (18) + your window"; if your
   state requires a longer minor tail, set your window accordingly or retain
   manually.

Also confirm any **behavioral-health-specific** or **psychotherapy-notes**
retention rule, which can differ from general medical records.

## Illustrative examples (verify — do not rely on these as current)

These are commonly-cited figures for orientation only. Confirm each against
current statute/board rule.

| State | Adult (commonly cited) | Minor (commonly cited) | Note |
|-------|------------------------|------------------------|------|
| Arizona | 6 yrs (A.R.S. §12-2297); 7 yrs board rule (§32-2936) | age of majority + 3 yrs | The example baked into the code comment |
| California | 7 yrs (varies by provider type) | until 18, or 1 yr past 18 | CMIA + board rules; psychotherapy-notes nuances |
| New York | 6 yrs | until 18 or 6 yrs, whichever later | MHL confidentiality applies to MH records |
| Texas | 7 yrs | until 21 | Board rule (22 TAC) |
| Illinois | varies | until 18 + N | MHDDCA governs MH records specifically |
| Florida | varies (often 5–7 yrs) | — | all-party recording state (see consent) |
| Massachusetts | often longer for hospitals | — | all-party recording state |
| Washington | varies | — | MHMDA + all-party recording state |

The empty cells are deliberate — do not infer a value; look it up.

## Interaction with other findings

- **Recording consent (S1):** whether you may record at all, and how consent
  must be captured, is also state-specific — see the recording-consent regime in
  `src/domain/jurisdictions.js` and the consent gate.
- **Breach notification (S5):** your state's breach law (deadlines, AG notice)
  keys off the same practice-state field.
- **Behavioral-health confidentiality (S3):** CA CMIA, IL MHDDCA, NY MHL §33.13
  and analogs impose disclosure rules stricter than HIPAA — see the state
  scope-determination doc.

## Maintenance

This file is a provider aid, not a compliance control. When a provider's state
gains a materially different rule, or counsel corrects a figure, update the row
and note the source. Keep the disclaimer prominent.
