# Compliance Open-Items Tracker

**Status:** Living tracker. This is the single place to record, assign, and close the open items identified in the Tahlk HIPAA & State-Law Compliance Audit. Update the status boxes and the owner/target columns as work progresses; add new items with the same structure rather than tracking them verbally.

**As of:** 2026-07-25
**Scope:** Technical, documentation, legal, and operational open items for Tahlk Solo. Contractual/third-party legal arrangements are tracked separately and are intentionally out of scope here.

**Status legend:** ☐ open · ◐ in progress · ☑ done · ⊘ blocked (needs external input)

---

## Summary

| ID | Item | Category | Owner | Target | Status |
|----|------|----------|-------|--------|--------|
| ENG-1 | Accounting of disclosures (§164.528) | Engineering | Claude Code | this cycle | ☑ |
| ENG-2 | Document the third transcription scratch artifact | Engineering / docs | _tbd_ | _tbd_ | ☐ |
| ENG-3 | Wire the JS audit actor to the provider profile | Engineering | _tbd_ | _tbd_ | ☐ |
| LEG-1 | State scope determinations (counsel sign-off) | Legal | _counsel_ | _tbd_ | ☐ |
| LEG-2 | State-conditional consent authorization language | Legal + Eng | _counsel_ | _tbd_ | ☐ |
| LEG-3 | Patient privacy notice — finalize & adopt | Legal + Product | _tbd_ | _tbd_ | ☐ |
| OPS-1 | Endpoint-hygiene setup requirements | Operational | _practice_ | ongoing | ☐ |
| OPS-2 | Screen-share / on-screen content protection | Engineering / Ops | _tbd_ | _tbd_ | ☐ |
| OPS-3 | Encrypted backup & recovery | Engineering / Ops | _tbd_ | _tbd_ | ☐ |

---

## Engineering — near-term

### ENG-1 — Accounting of disclosures (§164.528) &nbsp; ☑ done
**Finding:** HIPAA Privacy Rule — no patient-indexed accounting-of-disclosures capability.
**What / why:** `llm_audit` records every note-generation disclosure to the third-party AI service with actor/model/timestamp/byte-counts — the raw material for a disclosure accounting — but it was keyed by `encounter_id` only. A patient who invokes their §164.528 right could not be answered directly.
**Acceptance criteria:**
- [x] `patient_id` column added to `llm_audit` (idempotent migration for existing installs) and populated on each row at call time, snapshotted from the encounter in `notes::generate_note`.
- [x] A narrow, read-only `llm_audit_list_for_patient` command (+ `list_for_patient` helper) returning every disclosure for a patient, newest first, with the same DoS clamp as the encounter list.
- [x] Completeness caveat documented in code and asserted by a test: rows with a NULL `patient_id` (encounter-less or historical) are excluded and cannot produce a false match.
- [x] Tests: patient-scoping/ordering, NULL-exclusion, and the legacy-table migration round-trip.
**Closed by:** this cycle (see PR). **References:** `src-tauri/src/llm_audit.rs`, `src-tauri/src/notes.rs`, `src-tauri/src/encounters.rs` (`patient_id_for`).

### ENG-2 — Document the third transcription scratch artifact &nbsp; ☐
**Finding:** Documentation currency — an undocumented plaintext scratch file.
**What / why:** Transcription now also writes a JSON sidecar (`--output-json-full`) alongside the `.wav`/`.txt` scratch files. The control is intact (RAII `TempFileCleanup` + owner-only permissions + random suffix), so this is **not** an active leak — but the accepted-residual-risk paper trail still names only two files and references guard structs (`WavCleanup`/`TxtCleanup`) that were unified into `TempFileCleanup`. An undocumented PHI data flow is not, by our own discipline, an "accepted" one.
**Acceptance criteria:**
- [ ] `AUDIT-RESIDUAL-RISK.md` Item 2 and `hipaa-risk-assessment.md` Flow B name the `.json` sidecar explicitly.
- [ ] Guard-struct references updated to `TempFileCleanup`.
- [ ] The "no new unguarded write path" checklist re-run against {wav, txt, json}.
**References:** `src-tauri/src/whisper.rs`, `AUDIT-RESIDUAL-RISK.md`, `docs/security/hipaa-risk-assessment.md` (Flow B).

### ENG-3 — Wire the JS audit actor to the provider profile &nbsp; ☐
**Finding:** §164.312(a)(2)(i) / §164.312(b) — JS-side audit actor attribution.
**What / why:** `capabilities.js` `currentUser()` defaults to `null`, so the JS audit log (`auditLog.js`) falls back to a generic `'provider'` label. The Rust trails already stamp the server-derived provider name; wiring `currentUser()` to the provider profile brings the JS trail into parity.
**Acceptance criteria:**
- [ ] `currentUser()` reads the configured provider profile.
- [ ] `auditLog.js` entries attribute to the configured clinician.
- [ ] `hipaa-risk-assessment.md` §3.2 updated to reflect the closure.
**References:** `src/core/capabilities.js`, `src/core/auditLog.js`, `docs/security/hipaa-risk-assessment.md` §3.2.

---

## Legal / counsel-dependent

### LEG-1 — State scope determinations (counsel sign-off) &nbsp; ☐
**Finding:** State privacy law — S2/S3 determinations are drafts pending counsel.
**What / why:** Two scope-determination drafts exist as working positions. They need a licensed-counsel opinion, keyed to the states where Tahlk providers actually practice (now capturable via the provider practice-state field).
**Acceptance criteria:**
- [ ] Counsel review + sign-off on `state-consumer-health-data-scope-determination.md` (WA MHMDA / NV / CT).
- [ ] Counsel review + sign-off on `state-behavioral-health-confidentiality.md` (CA CMIA / IL MHDDCA / NY MHL).
- [ ] Sign-off checkboxes in each doc completed; any redlines folded in.
**References:** `docs/compliance/state-consumer-health-data-scope-determination.md`, `docs/compliance/state-behavioral-health-confidentiality.md`.

### LEG-2 — State-conditional consent authorization language &nbsp; ☐
**Finding:** S3 — some states require specific authorization to disclose MH records to a third party.
**What / why:** The S1 consent gate captures patient **consent to record**. Strict-consent states may additionally require a patient **authorization to disclose** mental-health information for AI note generation. Where counsel confirms this, extend the consent flow with approved wording.
**Acceptance criteria:**
- [ ] Counsel confirms which states require it and provides language.
- [ ] Consent flow adds a state-conditional authorization element.
- [ ] Tests for the state-conditional branch.
**References:** `src/solo/consentModal.js`, `src/solo/encounter/recordingSection.js`, `docs/compliance/state-behavioral-health-confidentiality.md`.

### LEG-3 — Patient privacy notice — finalize & adopt &nbsp; ☐
**Finding:** S7 — no patient-facing privacy notice.
**What / why:** A provider-adoptable template exists. It needs practice/counsel finalization and a distribution path, and its accuracy about third-party processing must match the real (separately-tracked) contractual state before distribution.
**Acceptance criteria:**
- [ ] Practice/counsel finalize the template wording.
- [ ] Distribution mechanism decided (in-app link, onboarding pack, or practice's own NPP supplement).
**References:** `docs/compliance/patient-privacy-notice-template.md`.

---

## Operational controls (practice)

### OPS-1 — Endpoint-hygiene setup requirements &nbsp; ☐
**Finding:** Multiple areas — controls Tahlk cannot enforce depend on the device.
**What / why:** OS login, full-disk encryption (FileVault/BitLocker), screen-lock-on-idle, and no shared/guest accounts are required complements to the in-app controls. These are the practice's responsibility and should be a documented, checked setup step.
**Acceptance criteria:**
- [ ] Setup/onboarding docs state these as required steps (not suggestions).
- [ ] A practice attests to them at deployment.
**References:** `GETTING_STARTED.md`, `docs/security/hipaa-risk-assessment.md` §3.

### OPS-2 — Screen-share / on-screen content protection &nbsp; ☐
**Finding:** Desktop risk — no on-screen content-protection flag; screen-share/remote-support tools can capture on-screen PHI.
**What / why:** Evaluate a platform content-protection option (e.g., Tauri window content protection) to exclude the window from capture, and/or document the exposure as an operational caution until/if implemented.
**Acceptance criteria:**
- [ ] Decision recorded: implement content-protection flag, or accept + document the residual.
- [ ] If accepted, the caution is stated in provider-facing docs.
**References:** Solo desktop window configuration; `docs/security/hipaa-risk-assessment.md`.

### OPS-3 — Encrypted backup & recovery &nbsp; ☐
**Finding:** Contingency (§164.308(a)(7)) — the encrypted database is the single critical asset with no in-app backup.
**What / why:** Loss of the device or the key is unrecoverable without a provider-maintained backup. Planned remediation is an in-app "export encrypted backup" feature; until then, the practice must maintain and periodically test an encrypted backup.
**Acceptance criteria:**
- [ ] Interim: backup responsibility + restore-test documented for the practice.
- [ ] Planned: encrypted-backup export feature scoped and tracked.
**References:** `docs/security/hipaa-risk-assessment.md` §5.

---

## Adding a new item

Append a row to the summary table and a detailed block using the same shape (Finding / What-why / Acceptance criteria / References). Keep this tracker synchronized with the audit artifact and the risk assessment — when an item closes, mark it ☑ here, update the referenced doc's status, and note the closing commit/PR.
