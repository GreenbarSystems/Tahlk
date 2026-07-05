# Pre-deploy security checklist — `tahlk-sync`

> **Status:** the service is FROZEN per
> [ADR 0001](../adr/0001-freeze-group-tier-and-sync.md). This checklist exists
> so that when unfreeze happens, the two known-Critical security gaps get
> closed **before** the first prod deploy — not discovered during it.
>
> If you are about to `cargo run --release` or `kubectl apply` this service
> against real tenants and any box below is unchecked, **stop**. These gaps
> break tenant isolation and open trivial DoS vectors.

## Why this file exists

The full [`tahlk-security-audit.md`](../../tahlk-security-audit.md) rated ten
findings against the Solo desktop client (C1–C2, H1–H6, M1–M10, L1–L5) — all
merged as of PR #6. Two additional findings apply to the sync server:

- **S1 — Auth middleware is a stub.** `server/src/auth.rs` only checks that the
  `Authorization` header starts with `Bearer ` and reads `x-tenant-id` /
  `x-provider-id` directly from client headers. Any client can read any tenant
  by sending `x-tenant-id: <target>`. Tenant isolation is currently a
  suggestion, not an enforcement.
- **S2 — No TLS termination, no rate limits, no request body size limit.**
  Plain HTTP on `0.0.0.0:8080`. No ambient defenses against large-body OOM,
  no rate limiting, no accidental-deploy fail-closed guard.

Both are non-issues *today* — the service is in-memory only and receives no
real traffic. Both become **Critical** on first prod deploy. They are
intentionally not fixed in the frozen tree; this checklist is the fix.

## S1 — Real JWT verification

Replace the stub in `server/src/auth.rs` with real verification.

- [ ] Add `jsonwebtoken` (or equivalent JWKS-aware verifier) to
      `server/Cargo.toml`.
- [ ] Fetch JWKS from the configured issuer at startup, refresh on `kid` miss,
      cache in memory with a bounded TTL.
- [ ] Verify `iss` matches the configured issuer.
- [ ] Verify `aud` matches the configured audience (`tahlk-sync`).
- [ ] Verify `exp` (not expired) and `nbf` (not before).
- [ ] Verify the signature against the JWKS key matching the token `kid`.
- [ ] Require a `tenant_id` claim (non-empty string).
- [ ] Require a `provider_id` claim (non-empty string).
- [ ] Derive `TenantCtx.tenant` and `TenantCtx.provider` **from the claims**;
      strip all use of `x-tenant-id` / `x-provider-id` request headers.
- [ ] Add `From<jsonwebtoken::errors::Error>` for `ApiError::Unauthorized` so
      verifier errors surface as 401 (never 500).
- [ ] On startup, refuse to serve traffic if the JWKS URL is unreachable
      (fail closed) — do not silently fall through to no-auth.
- [ ] Add integration tests that:
  - [ ] a valid token for tenant A is rejected when accessing tenant B's rows
        (should surface as 404 / 403, never 200);
  - [ ] an expired token is 401;
  - [ ] a token signed by the wrong key is 401;
  - [ ] a token missing `tenant_id` or `provider_id` is 401;
  - [ ] header-based `x-tenant-id` spoofing is **impossible** — the spoofed
        value never surfaces in `TenantCtx.tenant`.
- [ ] Update `server/README.md` `curl` examples to use a real dev token
      (issued by the local Auth0 tenant / dev IdP) rather than
      `Authorization: Bearer dev`.

**Concrete design pointer.** The comment at `server/src/auth.rs:6-17` already
describes the target design in prose. Turn the prose into code.

## S2 — Network defenses

Assume TLS is terminated upstream (nginx / ALB / Cloudflare / service mesh
sidecar). Add three in-process guards.

- [ ] Add `tower_http::limit::RequestBodyLimitLayer::new(1 * 1024 * 1024)` to
      the router — 1 MiB body cap. Encounter and audit payloads are hundreds
      of bytes; anything larger is either a bug or an attack.
- [ ] Add `tower_governor` (or equivalent) rate limiter, keyed on
      `TenantCtx.tenant` (i.e. per authenticated tenant, not per source IP —
      NAT'd hospitals share IPs). Starting envelope: **100 req/min per
      tenant**, adjustable per plan.
- [ ] Add fail-closed bind gate in `server/src/main.rs`: refuse to bind unless
      `TAHLK_ALLOW_INSECURE=1` is explicitly set. The intent is that a
      "just run it" accidental deploy without a TLS-terminating upstream
      hard-fails at startup instead of silently serving PHI over plaintext.
- [ ] Document the assumed deployment topology in `server/README.md`:
      client → TLS (nginx/ALB/CF) → tahlk-sync. Include the exact
      `X-Forwarded-Proto` / `X-Forwarded-For` handling.
- [ ] Add integration tests that:
  - [ ] a 2 MiB request body is rejected with `413 Payload Too Large` before
        the handler runs;
  - [ ] the 101st request in a rolling minute from the same tenant is
        rejected with `429 Too Many Requests`;
  - [ ] the service refuses to bind when `TAHLK_ALLOW_INSECURE` is unset,
        with a clear stderr message pointing to this document.

## Adjacent items to consider at the same time

Not S1/S2 themselves, but the same "before-deploy" review pass should:

- [ ] Swap `InMemoryStore` for the `PostgresStore` (`sqlx` + `SET app.tenant_id`
      per request for row-level security). Postgres RLS is the defense-in-depth
      layer for S1 — even if the JWT verification has a bug, RLS blocks
      cross-tenant reads at the database.
- [ ] Swap `InMemoryCache` for `RedisCache` (S4 from the audit — process-local
      cache is a correctness issue at >1 replica, not a security issue).
- [ ] Route the S3 error log through structured `tracing::error!(error = ?e)`
      with a redaction filter so DB error text doesn't leak SQL fragments
      containing tenant IDs.
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
