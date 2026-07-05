# tahlk-sync — Group-tier sync service

> ⛔ **FROZEN — not under active development.** Parked per
> [ADR 0001](../docs/adr/0001-freeze-group-tier-and-sync.md). It stays in CI so
> it keeps compiling, but no new work lands here until the unfreeze criteria are
> met (a signed Group customer **and** an audit-safe sync design). Focus is the
> single-user Solo desktop app. Do not extend this without revisiting the ADR.

> 🛑 **DO NOT DEPLOY.** This service has two open security findings from
> `tahlk-security-audit.md` that would be **Critical** on any real deployment:
>
> - **S1 — Auth middleware is a stub.** `src/auth.rs` only checks that the
>   `Authorization` header starts with `Bearer ` (no signature, no expiry, no
>   issuer/audience validation) and reads `x-tenant-id` / `x-provider-id`
>   directly from client headers. Any client can read any tenant by setting
>   `x-tenant-id: <target>`. There is **no tenant isolation** in effect today.
> - **S2 — No TLS, no rate limits, no body-size limit.** The listener is plain
>   HTTP on `0.0.0.0:8080`. There is no ambient defense against a large-body
>   OOM, no rate limiting, and no accidental-deploy fail-closed guard.
>
> These are intentionally unfixed because the service is frozen (see ADR 0001).
> They **must be resolved before any prod deploy** — see
> [`docs/security/pre-deploy-checklist.md`](../docs/security/pre-deploy-checklist.md).
> If you find yourself about to run this against real tenants, stop and read
> that checklist first.


Multi-tenant backend the Tahlk desktop app syncs to when a practice is on the
Group/Enterprise tier. Minimal but production-shaped: layered, tenant-isolated,
audit-preserving, and runnable with zero infrastructure (in-memory store/cache)
so the architecture can be exercised before Postgres/Redis are provisioned.

## Run

```bash
cd server
cargo run            # listens on :8080 (PORT to override)
```

```bash
# health
curl localhost:8080/healthz

# all requests are tenant-scoped + authenticated (stub auth: bearer + headers)
H='-H "Authorization: Bearer dev" -H "X-Tenant-Id: t1" -H "X-Provider-Id: p1"'

# upsert + read back (last-writer-wins via server updated_at)
curl -X PUT localhost:8080/v1/encounters/enc-1 $H \
  -H 'Content-Type: application/json' \
  -d '{"encounter_date":"2026-06-29","status":"draft","patient_alias":"P-001"}'
curl localhost:8080/v1/encounters?limit=50 $H

# append + list audit chain
curl -X POST localhost:8080/v1/encounters/enc-1/audit $H \
  -H 'Content-Type: application/json' \
  -d '{"actor":"Dr. Smith","action":"signed","entry_hash":"abc"}'
curl localhost:8080/v1/encounters/enc-1/audit $H
```

## Architecture

```
api (handlers)  ──▶  store: dyn EncounterStore   ──▶  InMemoryStore | PostgresStore
   │  auth: TenantCtx     cache: dyn Cache        ──▶  InMemoryCache | RedisCache
   └─ tenant-scoped       (traits = swap points)
```

`store` and `cache` are traits behind `Arc<dyn _>`. Production swaps the two
constructor lines in `main.rs`; handlers don't change.

## Production swap

Every item below is **mandatory** before any prod deploy — not aspirational.
See [`docs/security/pre-deploy-checklist.md`](../docs/security/pre-deploy-checklist.md)
for the checklist that gates unfreeze.

- **Store → Postgres** (`sqlx`): apply `migrations/0001_init.sql`. Per request,
  `SET app.tenant_id` from the JWT so row-level security enforces isolation at
  the database. Connection pool sized to instance count × pool size.
- **Cache → Redis**: shared across horizontally-scaled instances; the in-memory
  cache is per-process and only correct at one replica.
- **Auth (S1)**: replace the header/bearer stub in `auth.rs` with real JWT
  verification. Concretely: use the `jsonwebtoken` crate; verify signature
  against a JWKS fetched from the configured issuer (Auth0 / WorkOS / Clerk /
  self-hosted); validate `iss`, `aud`, `exp`, `nbf`; require `tenant_id` and
  `provider_id` claims; derive `TenantCtx.tenant` and `TenantCtx.provider` from
  those claims and **never** from headers. Add `From<jsonwebtoken::errors::Error>`
  for `ApiError::Unauthorized`. On startup, refuse to serve traffic if the
  JWKS URL is unreachable (fail closed). The comment on `auth.rs:8` already
  describes the target design; turn it into code.
- **Network defenses (S2)**: assume the deployment terminates TLS upstream
  (nginx / ALB / Cloudflare). In-process, add:
  - `tower_http::limit::RequestBodyLimitLayer::new(1 * 1024 * 1024)` — 1 MiB
    body cap so an oversized JSON blob can't OOM a replica.
  - `tower_governor` per-tenant rate limiter — 100 req/min per tenant is a
    reasonable starting envelope.
  - Fail-closed bind gate: refuse to bind unless `TAHLK_ALLOW_INSECURE=1` is
    explicitly set, so a "just run it" accidental deploy without a TLS-
    terminating upstream fails safely at startup.
- **Audio (PHI)**: never transits this service body. Client uploads encrypted
  WAV directly to object storage via a short-lived presigned URL; only the
  object key is stored here.

## Scaling notes

Stateless service → scale horizontally behind a load balancer (HPA on CPU/RPS).
State lives in Postgres (read replicas for list/get) and Redis. The audit table
is append-only and partitioned by month at volume. See the design doc for the
full topology, caching strategy, and HIPAA posture.
