# Managed Anthropic Key — Rollout Plan

**Decision (2026-06-26):** Adopt a vendor-managed Anthropic key for note generation so
practices don't bring their own key — **but gate it behind a HIPAA BAA chain.** Until every
gate below is cleared, **bring-your-own-key (BYO) remains the shipping default**, with
on-device generation as the privacy-maximizing alternative. Managed-key is a
**post-compliance onboarding upgrade**, not a launch feature.

> ⚠️ Do not enable the managed path in shipping builds until **every** box in
> §2 (Gating prerequisites) is checked. Turning it on early would route PHI through
> Tahlk infrastructure with *less* coverage than today's BYO model.

---

## 1. Why managed-key, and why it's gated

- **Onboarding win:** removes the "create a key at console.anthropic.com and paste it"
  step — the practice just signs in and it works.
- **Cost is a non-issue:** ~1–3¢/note on Haiku 4.5 ($1 / $5 per 1M input/output tokens).
  Even a Firm running thousands of notes/month is ~$30–60 against a $3,499/mo plan. COGS is
  buried at every tier.
- **The real catch:** today the transcript (PHI) goes device → Anthropic under the
  *customer's* account; Tahlk never touches it. Managed-key routes that PHI **through Tahlk
  servers**, which makes Tahlk a **Business Associate** and triggers the gates below.

Current note-gen path (BYO, direct):
`src/scribe/noteGenerator.js` → Tauri `generate_note` → `https://api.anthropic.com/v1/messages`
(see `src-tauri/src/notes.rs`, `generate_note`). Key is read from the OS keychain
(migrated off local SQLite; see `secrets.rs`) and never leaves the device except on the
Anthropic call.

---

## 2. Gating prerequisites (must ALL be true before enabling managed)

This checklist was originally written before Tahlk's compliance audit report
identified it as omitting several standard BAA-readiness elements (Medium
finding, area 10). Revised below — corrections and additions are marked.

**Legal / compliance**
- [x] **HIPAA readiness enabled on Anthropic's Console** for the dedicated
      organization the proxy will use (Console → Settings → Privacy →
      accept the standard BAA as an authorized legal representative, or a
      negotiated BAA via Anthropic sales if the standard terms don't fit).
      **BAA executed 2026-07-18.**
      **Correction (pre-existing, kept for history):** the earlier version of
      this checklist listed "Zero-Data-Retention (ZDR) enabled" as a *separate*
      item from the BAA. Per Anthropic's own documentation, HIPAA readiness and
      ZDR are **alternative** arrangements, not additive — enabling HIPAA
      readiness is the complete requirement; there is no separate ZDR step to
      also enable. Use a Console organization dedicated to this proxy, never
      one also used for unrelated/non-PHI work — HIPAA readiness is permanent
      and org-wide once enabled, and blocks any non-eligible API feature with a
      hard `400` error.
      **Empirical note (2026-07-18):** in the actual provisioning path Greenbar
      followed, Anthropic granted the BAA first and is treating ZDR provisioning
      on the dedicated org as a **separate, sequential approval step** — which
      is the opposite of what the correction paragraph above predicts. Both are
      recorded here so the discrepancy is visible; the operational status right
      now is "BAA signed, ZDR pending Anthropic approval," and
      `MANAGED-KEY-PROXY-CONTRACT.md` §3 and §7 (which independently require
      the upstream org to have ZDR enabled) remain the authoritative technical
      requirement. Reconcile this correction paragraph with Anthropic's current
      program terms once ZDR is approved and the operational picture is stable
      — do not silently delete either side of the contradiction before then.
- [ ] **ZDR provisioning approved by Anthropic** on the dedicated org —
      **pending Anthropic approval as of 2026-07-18**. Record the approval date
      here and in `docs/security/hipaa-risk-assessment.md` §2 Flow D the moment
      it lands. Until this box is checked, the managed-key proxy MUST NOT route
      real-PHI traffic even though the BAA itself is signed.
- [ ] **BAA template ready to sign with each practice** (Tahlk is the
      practice's BA), containing — at minimum, per 45 CFR §164.504(e)(2)'s
      required contract elements — the permitted/required uses of PHI, a
      prohibition on further use/disclosure beyond the agreement or as
      required by law, an obligation to implement appropriate safeguards,
      an obligation to report any use/disclosure not provided for (including
      breach notification, integrated with the
      [incident-response runbook](docs/security/incident-response-runbook.md) —
      that document's §6 division-of-responsibility language must be updated
      the moment this ships, since Greenbar becomes a direct BA for this flow
      rather than only for the desktop software), a flow-down requirement
      that Anthropic (the subcontractor) agrees to the same restrictions,
      support for patients' amendment/access/accounting-of-disclosure
      rights, availability of records to HHS, and defined return-or-destroy
      obligations at termination. **This is a real legal document — draft or
      review by a licensed healthcare attorney before it is shown to any
      practice; do not adapt a public template without that review.**
      **Status (2026-07-18):** in attorney drafting, week of 2026-07-13.
      Neither the provider↔Greenbar BAA nor the EULA is finalized or executed
      with any practice yet.
- [ ] Privacy policy / disclosures updated to state that, in managed mode, a
      (de-identified) transcript is sent to Anthropic under Greenbar's
      HIPAA-ready Console organization.
- [ ] **Minimum-necessary re-verification for the proxy path specifically**
      — the BYO path was independently verified to send only transcript +
      system prompt, no identifiers (see the compliance audit report). The
      proxy adds a new hop; confirm it doesn't introduce additional logging,
      buffering, or metadata (account id, request headers, etc.) that
      widens what leaves the device beyond what BYO already sends. Don't
      assume the BYO verification automatically carries over.

**Infrastructure**
- [ ] HIPAA-grade proxy stood up: TLS in transit, encryption at rest, access controls.
- [ ] **No PHI in logs/telemetry** — log metadata only (token counts, latency, account id).
- [ ] Per-account **metering + rate limits** (the Anthropic key is now Tahlk's — cap abuse/cost).
- [ ] Auth: app authenticates to the proxy with a Tahlk **account/session token**, never an
      Anthropic key. Anthropic key lives only server-side.
- [ ] **Least-privilege access control on the proxy's own infrastructure and
      logs** — name who inside Greenbar can reach proxy hosts/logs/metrics,
      and why. The proxy is new infrastructure that transiently touches PHI
      in flight; it needs the same "who can see this and why" discipline
      the desktop app's own design already applies (e.g. the API-key
      write-only boundary in `secrets.rs`).
- [ ] **Monitoring/alerting on the proxy service itself** — uptime, error
      rate, and anomalous-access alerting, distinct from the per-account
      abuse/cost metering above. A silently-failing or silently-compromised
      proxy is a detection gap the desktop app's local-only design never had
      to solve; the proxy introduces that need.
- [ ] SOC 2 Type II on the roadmap (per GTM plan) and at least in progress.

**Optional hardening (carry over from the privacy review)**
- [ ] De-identify the transcript before it leaves the device (defense-in-depth; not a BAA
      substitute — conversational BH transcripts leak identity regex can't catch).
- [ ] Stamp the generation engine ("managed cloud / HIPAA-ready") into the SHA-256 audit chain.

---

## 3. Target architecture — Anthropic-passthrough proxy

Design the proxy to speak the **Anthropic Messages API** so the client change stays a
base-URL + auth swap (no new request/response contract to invent):

```
BYO (today):   app ──(x-api-key: user key)─────────────▶ api.anthropic.com
Managed:       app ──(Authorization: Bearer <Tahlk token>)─▶ api.tahlk.com/anthropic ──┐
                                                                                       │ injects real key
                                                                                       │ (HIPAA-ready org),
                                                                                       │ forwards
                                                                                       ▼
                                                                              api.anthropic.com
```

The proxy receives the identical `/v1/messages` body, swaps the auth for the real
Anthropic key (from Greenbar's dedicated HIPAA-ready Console organization), forwards,
and streams the response back unchanged.

The full request/response contract — endpoints, auth, validation caps, error model, and HIPAA
logging rules — is specified in [`MANAGED-KEY-PROXY-CONTRACT.md`](./MANAGED-KEY-PROXY-CONTRACT.md).

---

## 4. Engineering changes (only once §2 is cleared)

Because the proxy is an Anthropic passthrough, the client change is small:

- `src-tauri/src/notes.rs` (`generate_note`): derive **endpoint + auth header** from a
  `generation_mode` setting.
  - `byo` (default): `https://api.anthropic.com/v1/messages`, header `x-api-key: <user key>`.
  - `managed`: `<TAHLK_API_BASE>/anthropic/v1/messages`, header
    `Authorization: Bearer <account token>`. Same JSON body.
- `src/solo/settingsModal.js` / `src/solo/onboarding.js`: when managed is enabled, hide the
  Anthropic-key field and show account sign-in instead; BYO remains for self-hosters.
- `src-tauri/tauri.conf.json` CSP `connect-src`: add the Tahlk proxy origin (and, in
  managed-only builds, you can drop `https://api.anthropic.com`).
- Feature gate so managed is **off by default** and only selectable once compliance flags are set.

> Intentionally **not implemented yet.** Writing the managed client path now means guessing
> the proxy/auth contract before the proxy and BAA exist — and contradicts the "BYO default
> until compliance" decision. Implement this section the moment §2 is green.

---

## 5. Shipping posture until then

- **Default:** BYO key (current behavior) — or on-device generation for zero-trust practices.
- **Managed:** disabled in shipping builds. Track §2; flip on only when fully green.
