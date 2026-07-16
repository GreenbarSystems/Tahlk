# Tahlk — Security Incident Response Runbook

**Status:** Active operational procedure
**Fulfills:** `docs/security/hipaa-risk-assessment.md` §6's planned remediation
("formalize [incident response] into a standalone incident-response runbook
— intake channel, triage steps, internal escalation, and template provider
notification — rather than leaving it as prose in [that] document only").
**Scope:** Tahlk Solo desktop application only. `server/` (tahlk-sync,
Group tier) is frozen per [ADR 0001](../adr/0001-freeze-group-tier-and-sync.md)
and out of scope until unfrozen — this document must be extended to cover it
before that happens, not silently assumed to already apply.
**Company context, stated plainly:** Greenbar Systems is a small team. This
runbook is written for that reality — one or a few people wearing every
role below — not for a scenario that assumes a dedicated security operations
function that doesn't exist. Structure it to scale is deliberate (named
roles, not named people), so it stays correct as the team grows, but every
step below must be executable by whoever is actually on call today.

---

## 1. Definitions

- **Security incident** — any suspected or confirmed event that could
  compromise the confidentiality, integrity, or availability of PHI, or of
  the systems that handle it. This is intentionally broader than "breach" —
  a lost laptop, a suspicious support request, a dependency CVE in a package
  Tahlk ships, and a confirmed data exposure are all incidents; not all of
  them turn out to be breaches.
- **Breach** — per 45 CFR §164.402, an impermissible use or disclosure of
  PHI that compromises its security or privacy, **presumed to be a breach**
  unless a documented risk assessment (§5 below) demonstrates a low
  probability that the PHI was compromised. The presumption runs in favor of
  notification, not against it — an ambiguous case is treated as a breach
  until the risk assessment says otherwise, not the reverse.
- **Tahlk-side incident** vs. **device-side incident** — because Solo is
  local-first with no Tahlk-operated backend holding PHI, most realistic
  incidents (device theft, an unlocked laptop, a provider's own account
  compromise) are the provider's own device-security responsibility, not a
  Tahlk software defect. This runbook's investigation step (§4) exists
  specifically to make that determination deliberately, not by default —
  see hipaa-risk-assessment.md §6's "Division of responsibility."

---

## 2. Roles

Named by function, not by person, so this stays correct as the team changes.

| Role | Responsibility |
|---|---|
| **Intake owner** | First point of contact for a reported incident. Logs it, starts the clock, and either handles triage directly or hands off. |
| **Investigation lead** | Owns determining scope, root cause, and whether PHI was actually implicated. Usually whoever has the most context on the affected code/system — for Tahlk today, that's whoever is doing engineering work. |
| **Notification owner** | Owns drafting and sending any required notifications (§6) and tracking the regulatory clock. Must NOT be the same disengaged bystander who only hears about it after the fact — this role is assigned explicitly at triage, not assumed. |
| **Decision owner** | Makes the final call on breach/no-breach determination and on when the incident is closed. At current company size this is very likely the same person as the other roles combined — that's fine; the point of naming the role is so the decision is made deliberately and recorded, not skipped. |

---

## 3. Intake

**Provider-facing channel:** a provider who suspects a device compromise,
loss, theft, or any other event that may have exposed patient data reports
it to Greenbar Systems support (the channel published in-product and in
`SETUP.md`/`GETTING_STARTED.md`). Reports should be treated as time-
sensitive from the moment they arrive — do not let one sit in an inbox
unacknowledged.

**Internally-discovered incidents:** not everything starts with a provider
report. Also treat as an intake event: a dependency vulnerability advisory
(GitHub Dependabot/`npm audit`/`cargo audit`) affecting a package Tahlk
ships, a code-review or audit finding that turns out to be live-exploitable
rather than latent, an unexpected pattern in diagnostics (if a provider has
opted in and shares a diagnostics export), or a report from a third party
(security researcher, etc.).

**On intake, immediately record (even if the details are still thin):**
- Date/time discovered, and by what channel.
- Who reported it (provider name/contact, or "internal — [source]").
- A short, factual description — resist the urge to editorialize about
  severity yet; that's §4's job.
- The intake owner's name and the timestamp intake was acknowledged.

This record is the seed of the incident's file — see §8 for what the
complete record must contain by closure.

---

## 4. Triage and investigation

**Timebound:** initial triage (assign an investigation lead, form a first-
pass severity read) should happen within **1 business day** of intake. This
is not the same as resolving the incident within a day — it's making sure
it isn't sitting untouched.

**Investigation questions, in order:**
1. **Is this a Tahlk software issue, or a device/account issue on the
   provider's side?** (E.g., a stolen unlocked laptop is a device issue; a
   vulnerability that lets a compromised WebView bypass the BAA gate is a
   Tahlk issue.) This determines who has the primary notification
   obligation under §6 below, not just how urgently Greenbar responds.
2. **What data could have been exposed?** Reference the data-flow map in
   `docs/security/data-flow-and-security-controls.md` and the flow
   inventory in `hipaa-risk-assessment.md` §2 to reason about what's
   actually reachable at the affected point, rather than assuming worst-case
   without checking.
3. **Is PHI encrypted at the point of exposure?** If the incident is, say, a
   stolen device and the SQLCipher database and audio remain encrypted with
   the keychain-held DEK intact and unexposed, that is directly relevant to
   the risk assessment in §5 — HIPAA's breach-notification safe harbor
   specifically for properly encrypted PHI. Don't skip this just because the
   incident sounds bad on its face.
4. **Is this exploit reproducible/ongoing, or a one-off/historical
   event?** An ongoing, exploitable vulnerability needs a fix shipped before
   or alongside notification, not after.
5. **Does this affect one provider, or is it a defect that could affect
   every install?** A code-level defect is a "how many were exposed"
   question that can't be answered from one report alone.

**Output of this step:** a written scope statement (what happened, what was
and wasn't exposed, how many parties are potentially affected, whether it's
ongoing) that §5's risk assessment is based on. If the investigation lead
can't answer one of the five questions above with confidence, that is
itself recorded — an unresolved unknown is not the same as "assumed no
impact."

---

## 5. Breach risk assessment

Per §164.402, run the four-factor assessment below for any incident that
reaches this step (i.e., anything not immediately and obviously a non-event).
Document the answer to each factor — this is what the "presumed breach
unless risk assessment shows low probability" standard actually means in
practice.

1. **The nature and extent of the PHI involved**, including the types of
   identifiers and the likelihood of re-identification.
2. **The unauthorized person who used the PHI or to whom the disclosure was
   made** (or, for a technical vulnerability, who realistically could have).
3. **Whether the PHI was actually acquired or viewed** (vs. merely
   theoretically accessible) — for a data-at-rest incident, whether the
   content was in fact encrypted with a key that remained secure is
   directly relevant here.
4. **The extent to which the risk to the PHI has been mitigated** (e.g., a
   promptly revoked credential, a remotely-triggerable-if-any encryption
   key rotation, confirmed device recovery).

**Outcome:** either (a) low probability of compromise, documented with
reasoning against all four factors — no breach-notification obligation, or
(b) presumed breach — proceed to §6.

---

## 6. Notification

**Timelines** (all measured from the date of **discovery**, not the date
the underlying event occurred):

| Recipient | Regulation | Deadline |
|---|---|---|
| Affected individuals | §164.404 | Without unreasonable delay, no later than 60 days |
| HHS | §164.408 | Annual log if <500 individuals; without unreasonable delay (≤60 days) if ≥500 |
| Covered entity (if Greenbar is acting as a business associate for the affected flow) | §164.410 | Without unreasonable delay, no later than 60 days |

**Division of responsibility** (per hipaa-risk-assessment.md §6): because
Solo is local-first with no Tahlk-operated backend holding PHI, the covered
entity — the individual provider or practice — is generally the party with
the direct notification obligation to their own patients for an incident
confined to their own device. Greenbar Systems' obligation is to (a)
promptly disclose anything discovered about the software itself so the
provider can meet that obligation on their own timeline, and (b)
independently evaluate its own notification duties as a business associate
wherever that role actually applies (e.g., the Anthropic-relay flow, or a
future managed-key proxy where Greenbar would hold that role directly).

**When Greenbar is investigating a Tahlk-side vulnerability affecting
multiple installs**, notify affected providers proactively, even before
every provider has individually reported an issue — don't wait for each one
to ask.

**Template — provider notification (Tahlk-side vulnerability):**

> Subject: Security notice regarding your Tahlk installation
>
> We're writing to let you know about a security issue we identified in
> Tahlk that [may have / did] affect [specific version(s) / feature].
>
> **What happened:** [factual, specific description — what the defect was,
> what it would have allowed, whether it was exploited or only exploitable]
>
> **What data was involved:** [be specific — "no patient data was involved"
> if genuinely true and confirmed, or the actual scope if not]
>
> **What we've done:** [the fix, and the version/date it shipped]
>
> **What you should do:** [update Tahlk to version X; anything providers
> need to check on their own end]
>
> If you believe this may affect your own HIPAA breach-notification
> obligations to your patients, we're available to answer technical
> questions about the scope of the underlying issue — see [support contact].
>
> — Greenbar Systems

**Template — HHS notification** follows the [OCR breach portal](https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf)
submission format directly; there is no separate Greenbar-authored template
for this recipient.

---

## 7. Remediation

- Ship the fix. If the incident revealed a live-exploitable defect, treat it
  with the same urgency as a High-severity compliance-audit finding — this
  runbook's existence doesn't replace normal engineering practice, it
  coordinates the compliance side of it.
- Confirm the fix actually closes the gap (the same verification discipline
  used throughout this codebase — tests, not assumption) before considering
  the incident's technical remediation complete.
- If the incident exposed a gap in this runbook itself (a step that didn't
  work, a timeline that was unrealistic, a missing escalation path), update
  this document as part of closing the incident — don't discover the same
  gap again next time.

---

## 8. Incident record and closure

Every incident, regardless of ultimate breach determination, gets a closed
record containing:

- Intake details (§3).
- Investigation findings and the five-question scope statement (§4).
- The four-factor risk assessment and its outcome (§5).
- Notifications sent, to whom, and when (§6) — or the documented reasoning
  for why none were required.
- The remediation shipped (§7), with a link to the actual commit/release.
- Date closed, and who made the closure decision (the decision owner from
  §2).

This record is itself PHI-adjacent documentation — store it consistent
with the same handling discipline as other compliance records (not
committed to a public repo if it contains real incident specifics; a
private tracker or a redacted summary in this repo, with full detail held
separately, is the right split).

---

## 9. Review cadence

Re-review this runbook:
- At minimum every 6 months, matching `hipaa-risk-assessment.md`'s own
  cadence.
- Immediately after running it for a real incident (§7's last bullet).
- Whenever the notification-responsibility division in §6 changes — most
  likely trigger: the managed-key proxy shipping, at which point Greenbar
  becomes a business associate for the note-generation flow directly rather
  than only for the desktop software itself, and §6's division-of-
  responsibility language must be revisited, not silently left describing
  the BYOK-only model.
- Whenever `tahlk-sync` moves toward unfreezing — this document's scope
  section explicitly excludes it today.

**Document history:**
- Initial version — fulfills the "planned remediation" named in
  `hipaa-risk-assessment.md` §6.
