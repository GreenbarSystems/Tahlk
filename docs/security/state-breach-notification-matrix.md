# State Breach-Notification Decision Aid

**Status:** Reference material / decision aid for incident response. **Not legal advice.** State breach-notification statutes change frequently and vary in fact-specific ways; every deadline, threshold, and content requirement below must be confirmed against current statute by counsel at the time of an actual incident.

**Date:** July 25, 2026

**Author:** Prepared by Claude Code (AI agent) at Ryan Moore's direction, based on the July 2026 state health-law compliance review (finding **S5**).

## Why this exists

The HIPAA risk assessment §6 and the [incident-response runbook](./incident-response-runbook.md) cover **federal** breach notification (§164.404 to individuals, §164.408 to HHS, §164.410 BA-to-CE). But **all 50 states have their own breach-notification laws**, and for a health app they frequently add obligations HIPAA does not:

- Notice to the **state Attorney General** (and sometimes state agencies or consumer-reporting agencies) above a threshold number of affected residents.
- **Shorter deadlines** than HIPAA's 60 days (several states require notice within **30 or 45 days**).
- Specific **content** requirements, and in some states **credit-monitoring** offers for certain data types.
- Special treatment of **medical information / health data** (e.g., California) and of **consumer health data** (WA MHMDA, which has its own consent/enforcement regime — see the consumer-health-data scope determination).

Because Tahlk Solo is local-first with no vendor-side PHI store, the **covered entity (the provider/practice) is usually the party with the direct state-law notification duty** for a device-confined incident; Greenbar's role is to support that (see runbook §6). This aid helps determine *which states' laws apply* and *what they require*.

## Which states' laws apply

State breach laws are keyed to the **residency of the affected individuals**, not the provider's location. So:

1. Enumerate the affected individuals and their PHI using the **`breach_scope`** report (`src-tauri/src/breach_scope.rs`, added for §164.404) — it is the who/what-PHI input to this whole process.
2. Determine each affected individual's **state of residence** (for a single-practice Solo install this is usually the practice's own state, captured on the provider profile, but confirm — patients may reside across a state line).
3. Apply **every** implicated state's law, plus HIPAA. When laws conflict, the **most protective / shortest-deadline** obligation generally governs.

## Decision procedure

For each implicated state:

1. **Trigger:** does the incident meet that state's definition of a reportable breach for the data types involved (many states have a risk-of-harm exception; medical/health-data breaches often do not)?
2. **Individual notice:** deadline (30 / 45 / 60 days / "without unreasonable delay"), required content, and method.
3. **AG / agency notice:** is there a resident-count threshold that triggers AG (and/or consumer-reporting-agency) notification, and what is its deadline?
4. **Extras:** credit monitoring, substitute notice rules for large breaches, and any health-data-specific statute (CA CMIA, WA MHMDA, etc.).
5. **Document** the analysis and every notice sent in the incident record (runbook §7).

## Illustrative examples (verify at incident time — do not rely on these)

Commonly-cited features, for orientation only:

| State | Individual-notice deadline (commonly cited) | AG / agency notice | Note |
|-------|---------------------------------------------|--------------------|------|
| California | Without unreasonable delay | AG if >500 CA residents | CMIA adds medical-info specifics |
| Florida | 30 days | AG if >500 FL residents | One of the shortest deadlines |
| Colorado | 30 days | AG if >500 CO residents | — |
| Texas | Without unreasonable delay, ≤60 days | AG if >250 TX residents | — |
| New York | Without unreasonable delay | AG + agencies (SHIELD Act) | Broad "private information" |
| Washington | 30 days | AG if >500 WA residents | MHMDA governs consumer health data separately |

Empty deadlines/thresholds elsewhere are deliberate — look them up per incident.

## Interaction with other controls

- **`breach_scope`** is the enumeration input (who/what PHI).
- **Provider practice state** (captured at onboarding) seeds the likely implicated state(s).
- **WA MHMDA** and other consumer-health-data laws may impose parallel obligations — see `docs/compliance/state-consumer-health-data-scope-determination.md`.
- The **incident-response runbook** remains the operational document; this aid is the state-law overlay on its notification step.

## Maintenance

Re-review at least annually and whenever a provider is onboarded in a new state. This is a decision aid, not a compliance control; the operative determinations at incident time are counsel's.
