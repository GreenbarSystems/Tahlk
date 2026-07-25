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
| ENG-2 | Document the third transcription scratch artifact | Engineering / docs | Claude Code | this cycle | ☑ |
| ENG-3 | Wire the JS audit actor to the provider profile | Engineering | Claude Code | this cycle | ☑ |
| LEG-1 | State scope determinations (counsel sign-off) | Legal | _counsel_ | _tbd_ | ⊘ |
| LEG-2 | State-conditional consent authorization language | Legal + Eng | _counsel_ | _tbd_ | ⊘ |
| LEG-3 | Patient privacy notice — finalize & adopt | Legal + Product | _tbd_ | _tbd_ | ⊘ |
| OPS-1 | Endpoint-hygiene setup requirements | Operational | _practice_ | ongoing | ◐ |
| OPS-2 | Screen-share / on-screen content protection | Engineering / Ops | Claude Code | this cycle | ☑ |
| OPS-3 | Encrypted backup & recovery | Engineering / Ops | Claude Code | this cycle | ☑ |

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

### ENG-2 — Document the third transcription scratch artifact &nbsp; ☑ done
**Finding:** Documentation currency — an undocumented plaintext scratch file.
**What / why:** Transcription also writes a JSON sidecar (`--output-json-full`) alongside the `.wav`/`.txt`. The control is intact (RAII `TempFileCleanup` + owner-only permissions + random suffix + the unclean-shutdown sweep), so this was **not** an active leak — but the accepted-residual-risk paper trail's primary description still named only two files and referenced guard structs (`WavCleanup`/`TxtCleanup`) that had been unified into `TempFileCleanup`.
**Acceptance criteria:**
- [x] `AUDIT-RESIDUAL-RISK.md` Item 2 and `hipaa-risk-assessment.md` Flow B name the `.json` sidecar explicitly, as one of three artifacts (`SCRATCH_EXTS`).
- [x] Guard-struct references updated to the unified `TempFileCleanup` (`_wav_cleanup` / `_cleanup` / `_json_cleanup`); the pre-release checklist's stale `WavCleanup`/`TxtCleanup` items and test names corrected.
- [x] The "no unguarded write path" checklist item clarified — the sidecar-written `.txt`/`.json` are covered by the guard/predicate + `SCRATCH_EXTS`/`is_scratch_artifact` pairing, not by the `fs::write` grep.
**Closed by:** this cycle (see PR). **References:** `src-tauri/src/whisper.rs`, `AUDIT-RESIDUAL-RISK.md`, `docs/security/hipaa-risk-assessment.md` (Flow B).

### ENG-3 — Wire the JS audit actor to the provider profile &nbsp; ☑ done (already wired)
**Finding:** §164.312(a)(2)(i) / §164.312(b) — JS-side audit actor attribution.
**Outcome:** the code was **already correct** — this item was documentation lag. `capabilities.js`'s base `currentUser: () => null` is overridden at startup by `installSoloCapabilities()` (`src/entry-solo.js`), which returns `{ name: profile.name, id: 'solo' }` read live from the provider profile, so `auditLog.js` already attributes to the configured clinician. Both the original audit reviewer and the H2 pass described the base default without accounting for the override.
**Acceptance criteria:**
- [x] `currentUser()` reads the configured provider profile — confirmed at `src/entry-solo.js` `installSoloCapabilities()`.
- [x] `auditLog.js` entries attribute to the configured clinician — via the overridden `currentUser()`; the `'provider'` fallback only applies before a profile name exists (onboarding requires one).
- [x] `hipaa-risk-assessment.md` §3.2/§4/§3-header corrected to reflect the wiring (the remaining nuance — the fixed `'solo'` id — is acceptable for a single-clinician tier).
**Closed by:** doc correction this cycle (no code change needed). **References:** `src/entry-solo.js`, `src/core/capabilities.js`, `src/core/auditLog.js`, `docs/security/hipaa-risk-assessment.md` §3.2.

---

## Legal / counsel-dependent

### LEG-1 — State scope determinations (counsel sign-off) &nbsp; ⊘ blocked on counsel (drafts ready)
**Finding:** State privacy law — S2/S3 determinations are drafts pending counsel.
**What / why:** Two scope-determination drafts exist as working positions. They need a licensed-counsel opinion, keyed to the states where Tahlk providers actually practice (now capturable via the provider practice-state field).
**Acceptance criteria:**
- [ ] Counsel review + sign-off on `state-consumer-health-data-scope-determination.md` (WA MHMDA / NV / CT).
- [ ] Counsel review + sign-off on `state-behavioral-health-confidentiality.md` (CA CMIA / IL MHDDCA / NY MHL).
- [ ] Sign-off checkboxes in each doc completed; any redlines folded in.
**References:** `docs/compliance/state-consumer-health-data-scope-determination.md`, `docs/compliance/state-behavioral-health-confidentiality.md`.

### LEG-2 — State-conditional consent authorization language &nbsp; ⊘ blocked on counsel
**Finding:** S3 — some states require specific authorization to disclose MH records to a third party.
**What / why:** The S1 consent gate captures patient **consent to record**. Strict-consent states may additionally require a patient **authorization to disclose** mental-health information for AI note generation. Where counsel confirms this, extend the consent flow with approved wording.
**Acceptance criteria:**
- [ ] Counsel confirms which states require it and provides language.
- [ ] Consent flow adds a state-conditional authorization element.
- [ ] Tests for the state-conditional branch.
**References:** `src/solo/consentModal.js`, `src/solo/encounter/recordingSection.js`, `docs/compliance/state-behavioral-health-confidentiality.md`.

### LEG-3 — Patient privacy notice — finalize & adopt &nbsp; ⊘ blocked on counsel/product (template ready)
**Finding:** S7 — no patient-facing privacy notice.
**What / why:** A provider-adoptable template exists. It needs practice/counsel finalization and a distribution path, and its accuracy about third-party processing must match the real (separately-tracked) contractual state before distribution.
**Acceptance criteria:**
- [ ] Practice/counsel finalize the template wording.
- [ ] Distribution mechanism decided (in-app link, onboarding pack, or practice's own NPP supplement).
**References:** `docs/compliance/patient-privacy-notice-template.md`.

---

## Operational controls (practice)

### OPS-1 — Endpoint-hygiene setup requirements &nbsp; ◐ documented; practice attestation open
**Finding:** Multiple areas — controls Tahlk cannot enforce depend on the device.
**What / why:** OS login, full-disk encryption (FileVault/BitLocker), screen-lock-on-idle, and no shared/guest accounts are required complements to the in-app controls. These are the practice's responsibility and should be a documented, checked setup step.
**Status:**
- [x] Documented as required operational controls in `hipaa-risk-assessment.md` §3.1 (OS login boundary), §3.3 (screen-lock complement), §3.4 (screen-capture caution), and §5 (FDE via backup guidance).
- [ ] *Open (practice-side):* surface as an explicit checked setup step in provider onboarding docs, and capture a practice attestation at deployment. Cannot be closed in the codebase — it is an operational control the practice owns.
**References:** `GETTING_STARTED.md`, `docs/security/hipaa-risk-assessment.md` §3.

### OPS-2 — Screen-share / on-screen content protection &nbsp; ☑ done (decision + documented)
**Finding:** Desktop risk — no on-screen content-protection flag; screen-share/remote-support tools can capture on-screen PHI.
**Outcome:** decision recorded in [ADR 0007](../adr/0007-window-content-protection.md) and the exposure documented as an operational caution. Enabling Tauri content protection is a real control but a product-level behavior change (blanks the window to *all* screen capture, including legitimate telehealth/support; no-op on Linux), so it is **not** force-enabled.
**Acceptance criteria:**
- [x] Decision recorded — ADR 0007: ship an **opt-in** Settings toggle (default off) rather than force-enable or config-only default-on; document the residual meanwhile.
- [x] Operational caution stated in provider-facing docs — `hipaa-risk-assessment.md` §3.4.
- [ ] *Follow-up (tracked, not blocking this item's close):* implement the opt-in toggle (`set_content_protected` wrapper + Settings persistence).
**Closed by:** ADR 0007 + §3.4 this cycle. **References:** `docs/adr/0007-window-content-protection.md`, `docs/security/hipaa-risk-assessment.md` §3.4.

### OPS-3 — Encrypted backup & recovery &nbsp; ☑ done (export shipped; restore is a follow-up)
**Finding:** Contingency (§164.308(a)(7)) — the encrypted database is the single critical asset with no in-app backup.
**Outcome:** the in-app **encrypted backup export** is built (Settings → Encrypted backup; [ADR 0008](../adr/0008-encrypted-backup-export.md)) — a single passphrase-encrypted SQLCipher file via `sqlcipher_export`, recoverable with the passphrase alone. Practice responsibility (store securely, remember passphrase, test recovery) is documented.
**Status:**
- [x] Interim guidance documented (`hipaa-risk-assessment.md` §5).
- [x] In-app "export encrypted backup" feature built — `backup.rs` (`export_encrypted_backup`), Settings UI, ADR 0008. Passphrase-keyed, separate from the login password, refuses to overwrite the live DB, metadata-only audit log. Tests: passphrase validation, SQL escaping, and a SQLCipher export→reopen round-trip (incl. wrong-passphrase rejection).
- [x] In-app **restore** built ([ADR 0009](../adr/0009-backup-restore-flow.md)) — `stage_backup_restore` (non-destructive) re-keys the backup into this install's DEK; a crash-safe staged swap in `db::open_database_with_dek` (`apply_pending_restore`) applies it on next launch, keeping a `.pre-restore.bak`. Passphrase + typed-`RESTORE` confirmation in Settings. **Records only** — audio is not in the backup (documented). Tests: re-key round-trip, wrong-passphrase rejection, swap-keeps-bak, unreadable-pending-discarded, no-op-without-pending.
- [ ] *Optional future enhancements:* bundle audio into export/restore; auto-clean the `.pre-restore.bak`.
**Closed by:** this cycle (see PRs). **References:** `src-tauri/src/backup.rs`, `src-tauri/src/db.rs`, `docs/adr/0008-encrypted-backup-export.md`, `docs/adr/0009-backup-restore-flow.md`, `docs/security/hipaa-risk-assessment.md` §5.

---

## Adding a new item

Append a row to the summary table and a detailed block using the same shape (Finding / What-why / Acceptance criteria / References). Keep this tracker synchronized with the audit artifact and the risk assessment — when an item closes, mark it ☑ here, update the referenced doc's status, and note the closing commit/PR.
