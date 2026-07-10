# Managed-Key Proxy — API Contract (v1 draft)

Companion to [`MANAGED-KEY-ROLLOUT.md`](./MANAGED-KEY-ROLLOUT.md). This is the contract the
Tahlk note-generation proxy must honor. It is an **Anthropic Messages-API passthrough**: the
desktop app sends the same `/v1/messages` body it sends today, the proxy swaps the auth for
Tahlk's real (ZDR-enabled) Anthropic key, enforces entitlement + safety caps, forwards, and
returns Anthropic's response unchanged.

> ⚠️ The transcript in every request body is **PHI**. The proxy is a HIPAA Business Associate.
> See §7 — it MUST NOT log, persist, or cache request/response bodies.

---

## 1. Principles

- **Thin passthrough.** The proxy adds auth, entitlement, metering, and safety caps — nothing
  about the prompt or note shape. Keep the body byte-identical to what the client sends.
- **Tahlk's key never leaves the server.** The client authenticates with a Tahlk account
  token; only the proxy holds the Anthropic key.
- **Fail closed.** Any auth/entitlement/cap failure → reject before calling Anthropic.
- **No PHI at rest, ever.** Bodies are forwarded in memory and discarded. Logs carry metadata only.

---

## 2. Base URL & endpoints

```
Base:  https://api.tahlk.com           (placeholder — confirm prod host)
```

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/anthropic/v1/messages` | Note generation passthrough (the only PHI endpoint) |
| `GET`  | `/v1/health` | Liveness; no auth; returns `{"status":"ok"}` |

> Path note: keep the trailing `/v1/messages` so the proxy can forward to
> `https://api.anthropic.com/v1/messages` by simple host swap. The `/v1/anthropic` prefix
> namespaces Tahlk's own API versioning separately from Anthropic's.

---

## 3. Authentication

**Client → Proxy**

```
Authorization: Bearer <tahlk_account_token>
```

- **Hybrid token model:**
  - **Access token** — short-lived **JWT** (suggested TTL ≤ 15 min) carrying `account_id`,
    `plan`, `jti`, `exp`. Validated statelessly per request (signature + `exp`), so the hot
    path needs no DB lookup.
  - **Revocation** — every request also checks `jti` against a cache-backed **denylist**, so a
    revoked/off-boarded account is cut off within the cache TTL rather than at token expiry.
    This is the HIPAA off-boarding lever.
  - **Refresh** — an **opaque, server-stored, revocable** refresh token (issued/rotated by the
    separate Tahlk identity service, not this proxy) mints new access tokens.
- **Never** an Anthropic key. The app has no Anthropic key in managed mode.
- Invalid/expired/bad-signature/denylisted → `401` (see §6). Account with no active
  subscription → `403`.

**Proxy → Anthropic** (added server-side; never accepted from the client)

```
x-api-key: <TAHLK_ANTHROPIC_KEY>          # ZDR-enabled org
anthropic-version: 2023-06-01
content-type: application/json
```

- The proxy **strips** any client-supplied `x-api-key` / `anthropic-version` and sets its own.
- The Anthropic org behind `TAHLK_ANTHROPIC_KEY` MUST have Zero-Data-Retention enabled.

---

## 4. Request

### Headers (client → proxy)

| Header | Required | Notes |
|---|---|---|
| `Authorization: Bearer …` | ✅ | Tahlk account token |
| `content-type: application/json` | ✅ | |
| `Idempotency-Key: <uuid>` | optional | If present, dedupe retries within a short window (see §5) |

### Body

The **unmodified Anthropic Messages API body** the app already builds today
(`src-tauri/src/notes.rs`, `generate_note`):

```json
{
  "model": "claude-haiku-4-5-20251001",
  "max_tokens": 2048,
  "system": "<template system prompt>",
  "messages": [
    { "role": "user", "content": "Generate a clinical note from the following session transcript:\n\n<transcript>" }
  ]
}
```

### Validation & safety caps (the proxy enforces; reject before forwarding)

Because requests spend Tahlk's key, the proxy MUST enforce:

| Rule | Limit | On violation |
|---|---|---|
| **Model allowlist** | `claude-haiku-4-5-20251001` (and alias `claude-haiku-4-5`) only | `400` `model_not_allowed` |
| **max_tokens cap** | `≤ 4096` | clamp to cap **or** `400` `max_tokens_too_large` (pick one — see Open Questions) |
| **Body size** | `≤ 1 MB` | `413` `request_too_large` |
| **Required fields** | `model`, `max_tokens`, `messages` present | `400` `invalid_request` |
| **No streaming (v1)** | reject `"stream": true` | `400` `streaming_unsupported` |
| **No server-side tools / extra params** | strip or reject unknown top-level fields | `400` `invalid_request` |

The proxy does **not** inspect or transform `system` / `messages` content (that's PHI). It
validates structure and the fields above only.

---

## 5. Proxy responsibilities (ordered)

1. **Authenticate** the bearer token → resolve `account_id`, `plan`. Fail → `401`.
2. **Authorize**: account has an active subscription/plan. Fail → `403`.
3. **Rate-limit / meter** for `account_id`:
   - **Per-minute rate limit** (abuse protection) — over → `429` with `Retry-After`.
   - **Monthly quota is soft-cap + overage** — exceeding the plan's included allotment does
     **not** block; the request proceeds and the excess accrues as metered overage (billed per
     plan). Record it; do **not** `429`.
   - **Abuse hard-ceiling** (e.g. N× the plan allotment) — over → `429` `rate_limited` (or
     `402` to force a billing action). Protects against a compromised client running up Tahlk's
     Anthropic bill.
4. **Validate** body + enforce §4 caps. Fail → `400`/`413`.
5. (Optional) **Idempotency**: if `Idempotency-Key` seen recently for this account, return the
   prior outcome without re-calling Anthropic.
6. **Forward** to `https://api.anthropic.com/v1/messages` with proxy-side headers (§3), body
   unchanged.
7. **Meter usage**: record `usage.input_tokens` / `usage.output_tokens` from the Anthropic
   response against `account_id` (numbers only — never the body).
8. **Return** Anthropic's response (status + JSON) to the client, mapping upstream errors per §6.
9. **Discard** request/response bodies from memory; emit a metadata-only log line (§8).

---

## 6. Responses & error model

### Success — `200`

Return the **Anthropic message object verbatim** (the app reads `content[0].text` and
`usage`). Do not reshape:

```json
{
  "id": "msg_…",
  "type": "message",
  "role": "assistant",
  "model": "claude-haiku-4-5-20251001",
  "content": [{ "type": "text", "text": "<generated note>" }],
  "stop_reason": "end_turn",
  "usage": { "input_tokens": 1234, "output_tokens": 512 }
}
```

### Errors — normalized envelope

All proxy-originated errors use one shape so the client can branch on `error.type`:

```json
{ "error": { "type": "rate_limited", "message": "Monthly note quota reached.", "retry_after": 3600 } }
```

| HTTP | `error.type` | Cause | Client should… |
|---|---|---|---|
| `401` | `unauthenticated` | Missing/invalid/expired token | Prompt re-sign-in |
| `403` | `subscription_inactive` | No active plan | Show billing/upgrade |
| `400` | `model_not_allowed` / `max_tokens_too_large` / `streaming_unsupported` / `invalid_request` | Failed §4 validation | Bug — surface generic failure |
| `413` | `request_too_large` | Transcript over size cap | Tell user the session is too long to process |
| `429` | `rate_limited` | Per-minute rate limit, or the abuse hard-ceiling — **monthly soft-cap does NOT 429** (it bills overage); include `Retry-After` + `retry_after` (s) | Back off / retry |
| `502` | `upstream_error` | Anthropic 4xx/5xx not otherwise mapped | Retryable; show transient failure |
| `503` | `upstream_unavailable` | Anthropic overloaded (`529`) | Retry with backoff |
| `504` | `upstream_timeout` | Anthropic call exceeded proxy deadline | Retry |

- **Upstream mapping:** Anthropic `401/403` (Tahlk's key problem) MUST surface as `502`
  `upstream_error` — **never** leak Tahlk-key auth state to the client. Anthropic `429` →
  proxy `429` (it's Tahlk's org limit, but client back-off is the right behavior). Anthropic
  `529` → `503`.
- **Never** include the request/response body, the Anthropic key, or `request-id` containing
  PHI context in `error.message`. (An Anthropic `request-id` value itself is safe to log
  server-side for support; don't echo PHI.)

---

## 7. Security & HIPAA requirements (non-negotiable)

- **No PHI persistence:** request `system`/`messages` and response `content` are never written
  to disk, DB, cache, queue, or APM payload. In-memory for the lifetime of the request only.
- **ZDR upstream:** the Anthropic org MUST have Zero-Data-Retention on.
- **TLS 1.2+** on both hops; HSTS on the public endpoint.
- **Logs/telemetry carry metadata only** (§8). Scrub bodies from any framework auto-logging
  (e.g., disable request-body capture in the web server / APM).
- **Access control + audit** on the proxy host and the `TAHLK_ANTHROPIC_KEY` secret (secrets
  manager; rotate on exposure).
- **Body size + timeouts** bounded to prevent resource abuse with Tahlk's key.
- De-identification is **client-side and optional** (see rollout plan) — the proxy assumes the
  body MAY contain PHI regardless and protects it accordingly.

---

## 8. Observability — metadata-only log schema

One structured line per request. **No PHI fields.**

```json
{
  "ts": "2026-06-26T14:03:00Z",
  "account_id": "acct_…",
  "request_id": "req_… (proxy-generated)",
  "anthropic_request_id": "req_… (from upstream response header)",
  "model": "claude-haiku-4-5-20251001",
  "input_tokens": 1234,
  "output_tokens": 512,
  "status": 200,
  "error_type": null,
  "latency_ms": 1840
}
```

---

## 9. Contract versioning

- Path-versioned at `/v1/…`. Breaking changes → `/v2/…`; run both during migration.
- The desktop app pins its proxy base URL + path; coordinate version bumps with a client release.

---

## 10. Client mapping (what changes in the app)

Only `generate_note` in `src-tauri/src/notes.rs` changes, driven by a `generation_mode` setting:

| | BYO (default today) | Managed |
|---|---|---|
| URL | `https://api.anthropic.com/v1/messages` | `<TAHLK_API_BASE>/v1/anthropic/v1/messages` |
| Auth header | `x-api-key: <user key>` | `Authorization: Bearer <account token>` |
| Body | unchanged | unchanged |
| Response parse | `content[0].text`, `usage` | identical |

Everything else (templates, sign-off, audit chain, export) is untouched.

---

## 11. Out of scope (v1)

- Streaming (`stream: true`) — reject for now; add as a passthrough of Anthropic SSE in v2 if
  the UI needs token-by-token output.
- Server-side tools, vision, batches — note-gen is a single text completion.
- Account/billing/auth issuance — a **separate** Tahlk identity service issues the bearer
  tokens this proxy consumes.

---

## 12. Open questions for the backend team

1. **max_tokens over cap:** clamp silently, or reject `400`? (Clamp is friendlier; reject is
   stricter — note quality at 4096 is fine either way.) — *open*
2. ✅ **RESOLVED — Token format: hybrid.** Short-lived JWT access token (stateless validation,
   carries `account_id`/`plan`) + per-request `jti` denylist for instant revocation, backed by
   an opaque revocable refresh token. See §3.
3. ✅ **RESOLVED — Quota model: soft-cap + overage.** Plan allotment is a soft cap; excess bills
   as metered overage (no hard block). The only `429`s are the per-minute rate limit and the
   abuse hard-ceiling. See §5 / §6. Per-tier allotments, overage rate, ceilings, and rate
   limits are specified in [`MANAGED-KEY-PLAN-ALLOTMENTS.md`](./MANAGED-KEY-PLAN-ALLOTMENTS.md).
4. **Region/residency:** any requirement to keep the proxy in a specific region for customer
   contracts? — *open*
5. **Idempotency window:** support it for safe client retries, and for how long? — *open*
