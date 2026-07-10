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

**Legal / compliance**
- [ ] **BAA with Anthropic** executed (Tahlk discloses PHI to Anthropic as a subcontractor BA).
- [ ] **Zero-Data-Retention (ZDR)** enabled on the Anthropic account used by the proxy.
- [ ] **BAA template ready to sign with each practice** (Tahlk is the practice's BA).
- [ ] Privacy policy / disclosures updated to state that, in managed mode, a
      (de-identified) transcript is sent to Anthropic under BAA + ZDR.

**Infrastructure**
- [ ] HIPAA-grade proxy stood up: TLS in transit, encryption at rest, access controls.
- [ ] **No PHI in logs/telemetry** — log metadata only (token counts, latency, account id).
- [ ] Per-account **metering + rate limits** (the Anthropic key is now Tahlk's — cap abuse/cost).
- [ ] Auth: app authenticates to the proxy with a Tahlk **account/session token**, never an
      Anthropic key. Anthropic key lives only server-side.
- [ ] SOC 2 Type II on the roadmap (per GTM plan) and at least in progress.

**Optional hardening (carry over from the privacy review)**
- [ ] De-identify the transcript before it leaves the device (defense-in-depth; not a BAA
      substitute — conversational BH transcripts leak identity regex can't catch).
- [ ] Stamp the generation engine ("managed cloud / BAA / ZDR") into the SHA-256 audit chain.

---

## 3. Target architecture — Anthropic-passthrough proxy

Design the proxy to speak the **Anthropic Messages API** so the client change stays a
base-URL + auth swap (no new request/response contract to invent):

```
BYO (today):   app ──(x-api-key: user key)─────────────▶ api.anthropic.com
Managed:       app ──(Authorization: Bearer <Tahlk token>)─▶ api.tahlk.com/anthropic ──┐
                                                                                       │ injects real key
                                                                                       │ + ZDR, forwards
                                                                                       ▼
                                                                              api.anthropic.com
```

The proxy receives the identical `/v1/messages` body, swaps the auth for the real
(ZDR-enabled) Anthropic key, forwards, and streams the response back unchanged.

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
