# Managed-Key — Plan Allotments & Limits (v1 draft)

Companion to [`MANAGED-KEY-PROXY-CONTRACT.md`](./MANAGED-KEY-PROXY-CONTRACT.md) (§5 soft-cap +
overage, §6 the `429`s). Defines, per plan tier, the **included note allotment**, **overage
rate**, **abuse hard-ceiling**, and **per-minute rate limit** the proxy enforces.

> **Framing:** inference is ~1–3¢/note (Haiku 4.5), so at $599–$3,499/mo these limits are **not**
> about protecting margin (gross margin stays ~98% in every realistic case — see §6). They exist
> to (a) cap abuse if an account token leaks, and (b) signal an upgrade when a practice
> genuinely outgrows its tier. Set them generous; treat overage as expansion, not a profit center.
>
> **All numbers below are DRAFT** — validate against real telemetry once managed-key ships, then
> tune. They are config, not contract: changeable without a client release.

---

## 1. Billing unit — a "note"

- **1 note = 1 successful note generation** = one `200` from
  `POST /v1/anthropic/v1/messages` (the proxy's only PHI endpoint).
- Failed requests (`4xx`/`5xx`) do **not** count against allotment.
- Per-note cost is bounded by the contract's §4 caps (model = Haiku, `max_tokens ≤ 4096`,
  body ≤ 1 MB), so a note has a predictable worst-case cost — see §6.

Notes (not tokens) are the customer-facing unit: it's the thing a provider understands
("how many sessions can I document"). Tokens are metered server-side for cost tracking only.

---

## 2. Usage basis (the assumption behind the numbers)

From the GTM analysis, independent behavioral health runs **8–14 sessions/provider/day**. With
~21 working days and some no-shows/manual notes, a **heavy provider ≈ 250–300 notes/month**;
typical is lower. The allotments below set the **included** level at **~400 notes/provider** —
comfortably above a heavy provider, so a normal practice never sees overage.

---

## 3. Tier allotments & limits

| Tier | Price/mo | Providers | **Included notes/mo** | Overage | **Monthly hard-ceiling** | Per-minute limit |
|---|---|---|---|---|---|---|
| **Solo** | $599 | 1 | **400** | $0.50/note | **1,200** (3×) | 6 / min |
| **Pro** | $1,699 | 2–3 | **1,200** | $0.50/note | **3,600** (3×) | 15 / min |
| **Firm** | $3,499 | 4–5 | **2,000** | $0.50/note | **6,000** (3×) | 25 / min |
| **Enterprise** | contact | 6+ | custom | custom | custom | custom |

Implied included = **~400 notes per provider** at the top of each band (Solo 400/1, Pro 1,200/3,
Firm 2,000/5) — consistent and generous vs the ~250–300 heavy-provider reality.

### What each limit does (maps to the proxy contract)

- **Included notes/mo (soft cap):** notes 1…N run normally. Crossing N does **not** block —
  the request proceeds and each note above N records **$0.50 overage** (contract §5: "do not
  `429`"). It's the upgrade-signal lever.
- **Monthly hard-ceiling (3× included):** the abuse backstop. At the ceiling the proxy returns
  `429 rate_limited` (or `402` to force a billing action) until the next cycle or a plan change.
  This is what stops a **leaked token** from turning uncapped overage into an unbounded bill —
  the trade-off you accept by making overage uncapped by default.
- **Per-minute limit:** abuse/runaway protection. A real note-gen follows a finished session and
  takes seconds; even a Firm with 5 providers wrapping up at once won't legitimately exceed
  ~25/min. Over → `429` with `Retry-After` (contract §6).

---

## 4. Why overage is $0.50/note (flat)

- **Painless for real outliers:** a Solo provider running 100 notes over their 400 pays $50 on
  top of $599 — noticeable, not punitive.
- **Strong margin, but that's incidental:** $0.50 is ~20–40× the ~1.3–2.5¢ COGS; the point is
  it's a clean, predictable number, not nickel-and-diming.
- **Upgrade signal:** sustained overage is the cue to move up a tier (or, for a high-volume
  *solo*, just keep paying overage — Pro/Firm are about *adding providers*, not volume, so
  overage is the right lever for a single power-user).
- Flat across tiers in v1 for simplicity. A volume-discounted overage for Firm is a possible
  later knob (§7).

---

## 5. Worked examples

| Scenario | Notes/mo | Outcome |
|---|---|---|
| Solo, typical | 250 | Inside 400 — **$599 flat** |
| Solo, heavy | 380 | Inside 400 — **$599 flat** |
| Solo, power user | 650 | 400 incl + **250 × $0.50 = $125 overage** → **$724**; nudge: "you're consistently over" |
| Solo, leaked token / runaway | hits 1,200 | **Hard-ceiling `429`** + alert; bill capped at $599 + 800×$0.50 = **$999** before stop |
| Pro, 3 providers typical | ~750 | Inside 1,200 — **$1,699 flat** |
| Pro, 3 busy providers | ~1,050 | Inside 1,200 — **$1,699 flat** |
| Firm, 5 providers typical | ~1,250 | Inside 2,000 — **$3,499 flat** |
| Firm, 5 heavy providers | ~1,500 | Inside 2,000 — **$3,499 flat** |

The design intent shows in the table: **every realistic practice lands inside its include** and
pays the flat subscription. Overage and the ceiling only fire on genuine outliers or abuse.

---

## 6. Margin sanity (COGS is trivial — limits aren't protecting it)

Per-note COGS on Haiku 4.5 ($1 / $5 per 1M in/out): ~**$0.013** (med-mgmt, ~6K in + 1.2K out)
to ~**$0.025** (long intake, ~15K in + 2K out). Worst case at the `max_tokens` cap stays well
under ~$0.03.

| Tier | Price/mo | Included notes | Included COGS @ $0.025 | Gross margin on included |
|---|---|---|---|---|
| Solo | $599 | 400 | ~$10 | **~98%** |
| Pro | $1,699 | 1,200 | ~$30 | **~98%** |
| Firm | $3,499 | 2,000 | ~$50 | **~98%** |

Even a token running all the way to its **hard ceiling** at heavy-note cost (e.g. Solo 1,200 ×
$0.025 = **$30**) is immaterial against the subscription. **Conclusion:** the allotments exist
for abuse-bounding and upgrade-signaling, not unit economics.

---

## 7. Knobs to tune later (with real data)

- **Included levels:** if telemetry shows heavy providers above ~350 notes/mo, raise the
  ~400/provider basis.
- **Overage rate:** $0.50 flat now; consider a volume-discounted overage for Firm/Enterprise.
- **Hard-ceiling multiplier:** 3× is a starting point; tighten if abuse appears, loosen if
  legitimate spikes hit it.
- **Per-minute limits:** raise if concurrent multi-provider Firms hit `429`s legitimately.
- **Annual plans / committed-use discounts:** out of scope here (pricing is monthly today).
- **Token-based metering:** if note sizes vary wildly, consider metering tokens instead of
  notes — but notes are the clearer customer unit; only switch if data forces it.

---

## 8. Dependencies

- These limits are **plan config** consumed by the proxy (contract §5/§6) and by the Tahlk
  identity/billing service that issues the bearer tokens (it stamps `plan` into the JWT).
- Like everything managed-key, this ships **only after the BAA chain is cleared**
  ([`MANAGED-KEY-ROLLOUT.md`](./MANAGED-KEY-ROLLOUT.md) §2). Until then it's a spec, not a
  live config.
