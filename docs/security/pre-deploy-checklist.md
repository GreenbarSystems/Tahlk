# Pre-deploy security checklist — `tahlk-sync`

> **Status:** the service remains FROZEN per
> [ADR 0001](../adr/0001-freeze-group-tier-and-sync.md). **S1 and S2 are now
> fixed** in code (scoped freeze exception under ADR 0001 unfreeze criterion #3;
> see the ADR and `server/README.md`) — their boxes below are checked. **S3
> (redacted structured error logging) and S4 (swap-in `RedisCache`) are now
> fixed in code as well**, under the same scoped exception — their boxes below
> are checked. This does **not** unfreeze the service: the other unfreeze
> criteria (signed Group customer, audit-safe sync design) are unmet and the
> remaining adjacent items below (Postgres RLS, schema drift) are still open.
>
> If you are about to `cargo run --release` or `kubectl apply` this service
> against real tenants and any box below is unchecked, **stop**. These gaps
> break tenant isolation and open trivial DoS vectors.

## Why this file exists

The full `tahlk-security-audit.md` rated ten findings against the Solo
desktop client (C1–C2, H1–H6, M1–M10, L1–L5) — all merged as of PR #6.
**That file is not present in this repository or its git history** — it was
never committed here; the finding IDs it originally assigned survive only as
in-code `[audit XX]` comments (grep the codebase for the exact ID) and as a
consolidated re-verification in
[`docs/security/hipaa-risk-assessment.md`](./hipaa-risk-assessment.md), which
is the current authoritative source for the Solo desktop client's compliance
status. Treat any citation of `tahlk-security-audit.md` elsewhere in this repo
the same way. Two additional findings apply to the sync server:

- **S1 — Auth middleware is a stub.** `server/src/auth.rs` only checks that the
  `Authorization` header starts with `Bearer ` and reads `x-tenant-id` /
  `x-provider-id` directly from client headers. Any client can read any tenant
  by sending `x-tenant-id: <target>`. Tenant isolation is currently a
  suggestion, not an enforcement.
- **S2 — No TLS termination, no rate limits, no request body size limit.**
  Plain HTTP on `0.0.0.0:8080`. No ambient defenses against large-body OOM,
  no rate limiting, no accidental-deploy fail-closed guard.

Both would become **Critical** on first prod deploy. They have now been
**remediated in code** as a scoped exception to the freeze (ADR 0001 unfreeze
criterion #3); the S1/S2 sections below record the completed work. The
service stays frozen for the remaining unfreeze criteria.

## S1 — Real JWT verification

Replace the stub in `server/src/auth.rs` with real verification.

- [x] Add `jsonwebtoken` (or equivalent JWKS-aware verifier) to
      `server/Cargo.toml`.
- [x] Fetch JWKS from the configured issuer at startup, refresh on `kid` miss,
      cache in memory with a bounded TTL.
- [x] Verify `iss` matches the configured issuer.
- [x] Verify `aud` matches the configured audience (`tahlk-sync`).
- [x] Verify `exp` (not expired) and `nbf` (not before).
- [x] Verify the signature against the JWKS key matching the token `kid`.
- [x] Require a `tenant_id` claim (non-empty string).
- [x] Require a `provider_id` claim (non-empty string).
- [x] Derive `TenantCtx.tenant` and `TenantCtx.provider` **from the claims**;
      strip all use of `x-tenant-id` / `x-provider-id` request headers.
- [x] Add `From<jsonwebtoken::errors::Error>` for `ApiError::Unauthorized` so
      verifier errors surface as 401 (never 500).
- [x] On startup, refuse to serve traffic if the JWKS URL is unreachable
      (fail closed) — do not silently fall through to no-auth.
- [x] Add integration tests that:
  - [x] a valid token for tenant A is rejected when accessing tenant B's rows
        (should surface as 404 / 403, never 200) — covered by the
        header-spoof test: the store is keyed on the verified tenant, so a
        tenant-A token never surfaces tenant-B rows;
  - [x] an expired token is 401;
  - [x] a token signed by the wrong key is 401;
  - [x] a token missing `tenant_id` or `provider_id` is 401;
  - [x] header-based `x-tenant-id` spoofing is **impossible** — the spoofed
        value never surfaces in `TenantCtx.tenant`.
- [x] Update `server/README.md` `curl` examples to use a real dev token
      rather than `Authorization: Bearer dev`.

**Concrete design pointer.** The comment at `server/src/auth.rs:6-17` already
describes the target design in prose. Turn the prose into code.

## S2 — Network defenses

Assume TLS is terminated upstream (nginx / ALB / Cloudflare / service mesh
sidecar). Add three in-process guards.

- [x] Add `tower_http::limit::RequestBodyLimitLayer::new(1 * 1024 * 1024)` to
      the router — 1 MiB body cap. Encounter and audit payloads are hundreds
      of bytes; anything larger is either a bug or an attack.
- [x] Add a rate limiter (`governor`), keyed on
      `TenantCtx.tenant` (i.e. per authenticated tenant, not per source IP —
      NAT'd hospitals share IPs). Starting envelope: **100 req/min per
      tenant**, adjustable per plan.
- [x] Add fail-closed bind gate in `server/src/main.rs`: refuse to bind unless
      `TAHLK_ALLOW_INSECURE=1` is explicitly set. The intent is that a
      "just run it" accidental deploy without a TLS-terminating upstream
      hard-fails at startup instead of silently serving PHI over plaintext.
- [x] Document the assumed deployment topology in `server/README.md`:
      client → TLS (nginx/ALB/CF) → tahlk-sync. Note: the service intentionally
      does **not** consume `X-Forwarded-Proto` / `X-Forwarded-For` — rate
      limiting keys on the verified JWT tenant, not the source IP, so no
      forwarded-header trust is required.
- [x] Add integration tests that:
  - [x] a 2 MiB request body is rejected with `413 Payload Too Large` before
        the handler runs;
  - [x] the 101st request in a rolling minute from the same tenant is
        rejected with `429 Too Many Requests`;
  - [x] the service refuses to bind when `TAHLK_ALLOW_INSECURE` is unset
        (non-loopback address), with a clear stderr message pointing operators
        at the opt-in — covered by the `enforce_bind_policy` unit tests.

## Adjacent items to consider at the same time

Not S1/S2 themselves, but the same "before-deploy" review pass should:

- [ ] Swap `InMemoryStore` for the `PostgresStore` (`sqlx` + `SET app.tenant_id`
      per request for row-level security). Postgres RLS is the defense-in-depth
      layer for S1 — even if the JWT verification has a bug, RLS blocks
      cross-tenant reads at the database. **Partially addressed (2026-07-16):**
      a real cross-tenant key-collision bug was found and fixed in
      `InMemoryStore` itself — `append_audit`/`list_audit` used a composite
      string key (`format!("{tenant}::{encounter_id}")`) that an
      `encounter_id` containing the same separator could collide into a
      different tenant's key. Replaced with a properly nested
      `HashMap<tenant, HashMap<encounter_id, entries>>`, eliminating the
      ambiguity structurally. This closes a real bug but is not a substitute
      for the Postgres/RLS swap above — that remains fully open, and this box
      stays unchecked.
- [x] Swap `InMemoryCache` for `RedisCache` (S4 from the audit — process-local
      cache is a correctness issue at >1 replica, not a security issue). The
      swap-in `RedisCache` now exists behind the `Cache` trait; select it with
      `TAHLK_CACHE_BACKEND=redis` (+ `TAHLK_REDIS_URL`). `main` fails closed if a
      configured Redis is unreachable. A single instance may keep the default
      in-memory cache; **any horizontally-scaled deployment must set
      `TAHLK_CACHE_BACKEND=redis`** or replicas will serve stale reads past an
      invalidation. See `server/README.md`.
- [x] Route the S3 error log through structured `tracing::error!(error = …)`
      with a redaction filter so DB error text doesn't leak SQL fragments
      containing tenant IDs. Internal-error and JWT-failure logs now pass a
      redacted detail in a named `error` field (URL userinfo + sensitive
      `key=value` pairs masked) while the log *message* stays a stable static
      string. Promotion to a per-field `tracing_subscriber` `Layer` is the
      documented follow-up once the Postgres store lands (see `error.rs`).
- [ ] Confirm the two schema drift points between desktop and server
      (`audio_path` vs `audio_object_key`, etc. — see ADR 0001) are resolved
      as part of unfreeze planning, not shipped with a schema split.

## Sign-off

Before flipping traffic to a real deployment, the owning engineer must:

1. Check every box above.
2. Attach the artifact links (PR numbers, test run IDs, JWKS URL response) to
   the ADR 0001 unfreeze record.
3. Have a second engineer independently verify that S1's `x-tenant-id` header
   is being ignored on the deployed instance (curl with spoofed header, expect
   401 or the token's real tenant, never the spoofed one).

Anything short of this reintroduces S1/S2 by omission.
