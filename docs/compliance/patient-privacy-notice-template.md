# Patient Privacy Notice — Template for Providers

**Status:** Template for a provider/practice to review, adapt, and adopt. **Not legal advice, and not an official Notice of Privacy Practices (NPP).** A practice's HIPAA NPP and any state-required notices are the practice's responsibility; this template gives providers accurate, plain-language building blocks describing how Tahlk handles patient information so they can incorporate it into their own patient-facing disclosures.

**Date:** July 25, 2026

**Author:** Prepared by Claude Code (AI agent) at Ryan Moore's direction, based on the July 2026 state health-law compliance review (finding **S7**).

## How to use this

Tahlk previously had no patient-facing privacy notice of any kind (finding S7; `MANAGED-KEY-ROLLOUT.md` also lists a privacy policy as outstanding). Several state consumer-health-data laws (e.g., WA MHMDA) and behavioral-health confidentiality statutes expect patient-facing disclosure. This template is written for the **provider** to adapt to their practice, jurisdiction, and counsel's guidance — fill in the bracketed placeholders and delete anything that does not apply.

---

## [Practice Name] — How We Use Tahlk to Document Your Visit

**Recording your visit.** With your consent, we use Tahlk to record the audio of your visit and create a written clinical note. We will ask for your consent before recording, and you may decline or ask us to stop at any time. [In [State], all parties must consent to being recorded; we will obtain your consent before we begin.]

**Where your information is stored.** The recording, transcript, and note are stored **encrypted on the provider's device**. Tahlk does not keep a copy on its own servers.

**How the note is created (AI assistance).** To turn the conversation into a structured note, the transcript is sent securely to **Greenbar Systems**, our documentation vendor, which uses an artificial-intelligence service to draft the note. Greenbar acts as our **Business Associate** under a signed agreement, and its AI subcontractor operates under a **zero-data-retention** arrangement — your information is **not used to train AI models** and is **not sold**. Every AI-drafted note is **reviewed and signed by your provider**, who is responsible for its content.

**Your choices and rights.** You may ask us to [access / correct / delete] information in your record, and to provide an accounting of certain disclosures, consistent with HIPAA and [State] law. Speak with [contact] to make a request. [Add any state-specific rights, e.g., California CMIA / CCPA, Washington MHMDA.]

**Questions.** Contact [privacy contact / officer], [phone/email].

---

## Notes for the provider (delete before sharing with patients)

- **Confirm the recording-consent language** against your state's law. Tahlk classifies all-party-consent states conservatively (see `src/domain/jurisdictions.js`) and prompts you to attest patient consent before recording, but the patient-facing wording is yours to finalize.
- **The AI/BAA/ZDR paragraph is only accurate once the contracts are executed** — this is the same **C1** dependency tracked in `docs/security/hipaa-risk-assessment.md` §2 Flow D. Do not distribute a notice that asserts a BAA/ZDR arrangement that is not yet in force.
- **Behavioral-health specifics:** if you practice in a strict-consent state (e.g., IL/CA/NY — see `state-behavioral-health-confidentiality.md`), counsel may require additional authorization language for disclosing mental-health information to a third party.
- **Keep this synchronized** with your HIPAA NPP; this template supplements, and does not replace, your NPP.
