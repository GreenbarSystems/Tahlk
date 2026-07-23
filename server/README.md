# tahlk-sync — Group-tier sync service

> ⛔ **FROZEN — not under active development.** Parked per
> [ADR 0001](../docs/adr/0001-freeze-group-tier-and-sync.md). It stays in CI so
> it keeps compiling, but no new work lands here until the unfreeze criteria are
> met (a signed Group customer **and** an audit-safe sync design). Focus is the
> single-user Solo desktop app. Do not extend this without revisiting the ADR.

> 🔐 **Security findings S1, S2, S3 and S4 are now fixed** (see
> [`docs/security/pre-deploy-checklist.md`](../docs/security/pre-deploy-checklist.md)).
> These landed as scoped, security/correctness-only exceptions to the freeze,
> permitted by ADR 0001's own unfreeze criterion #3 — **they do not unfreeze the
> service.** The other two criteria (a signed Group customer **and** an
> audit-safe sync design) remain unmet, so this must not be deployed against
> real tenants yet.
>
> - **S1 — real JWT auth (fixed).** `src/auth.rs` now verifies the token
>   signature against a JWKS fetched from the configured issuer, validates
>   `iss` / `aud` / `exp` / `nbf`, and derives `TenantCtx.tenant` /
>   `TenantCtx.provider` **only** from the token's `tenant_id` / `provider_id`
>   claims. The old header-trust path is gone — `x-tenant-id` is ignored.
>   Startup fails closed if the JWKS is unreachable.
> - **S2 — network defenses (fixed).** A 1 MiB request-body limit, a per-tenant
>   rate limit (100 req/min, keyed on the verified tenant), and a fail-closed
>   bind gate (refuses a non-loopback bind unless `TAHLK_ALLOW_INSECURE=1`) are
>   in place. **TLS termination remains an upstream responsibility** (nginx /
>   ALB / Cloudflare); this service still speaks plain HTTP behind that proxy.
> - **S3 — redacted structured error logging (fixed).** `src/error.rs` no longer
>   string-interpolates raw error text into log messages. Internal-error and
>   JWT-failure logs carry a redacted detail in a named `error` field (URL
>   userinfo and sensitive `key=value` pairs masked) while the message stays a
>   stable static string. Promotion to a per-field `tracing_subscriber` `Layer`
>   is the documented follow-up once the Postgres store lands.
> - **S4 — swap-in `RedisCache` (fixed).** A shared-cache backend now exists
>   behind the `Cache` trait. Single instances keep the default in-memory cache;
>   **any horizontally-scaled deployment must set `TAHLK_CACHE_BACKEND=redis`**
>   (see [Cache backend](#cache-backend)) or replicas will serve stale reads past
>   an invalidation. Startup fails closed if a configured Redis is unreachable.


Multi-tenant backend the Tahlk desktop app syncs to when a practice is on the
Group/Enterprise tier. Minimal but production-shaped: layered, tenant-isolated,
audit-preserving, and runnable with zero infrastructure (in-memory store/cache)
so the architecture can be exercised before Postgres/Redis are provisioned.

## Run

The service binds loopback by default and requires real JWT auth config. For
production, point it at your IdP's JWKS:

```bash
cd server
export TAHLK_JWT_ISSUER="https://your-idp.example/"
export TAHLK_JWT_AUDIENCE="tahlk-sync"          # default; override if needed
export TAHLK_JWKS_URL="https://your-idp.example/.well-known/jwks.json"
# Token issuance for POST /v1/devices/register. The RS256 private key whose
# PUBLIC half is published in the JWKS above under $TAHLK_JWT_SIGNING_KID, so the
# tokens it mints verify against the same JWKS. Startup fails closed if either is
# missing/malformed.
export TAHLK_JWT_SIGNING_KEY="$(cat signing-key.pem)"
export TAHLK_JWT_SIGNING_KID="tahlk-desktop-2026"
# Binding a non-loopback address requires an explicit opt-in, since TLS is
# terminated upstream (see below):
# export TAHLK_ALLOW_INSECURE=1
# export TAHLK_BIND_ADDR=0.0.0.0  # override the bind IP; defaults to 127.0.0.1
cargo run            # listens on 127.0.0.1:8080 (PORT to override)
```

For local development without a real IdP, a symmetric HS256 bypass is available
(never enable in production):

```bash
export TAHLK_AUTH_DEV_BYPASS=1
export TAHLK_AUTH_DEV_HS256_SECRET="dev-only-shared-secret"
export TAHLK_JWT_ISSUER="https://issuer.test/"
export TAHLK_JWT_AUDIENCE="tahlk-sync"
cargo run
```

```bash
# health (unauthenticated — for orchestrator probes)
curl localhost:8080/healthz

# device registration (unauthenticated — a first-time device has no token yet).
# Returns a long-lived (90-day) bearer token whose tenant_id IS the device_id;
# idempotent by device_id, and per-source-IP rate limited. Use the returned
# token as $TOKEN for the /v1 calls below.
curl -X POST localhost:8080/v1/devices/register \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"a-random-client-generated-opaque-id"}'
# -> {"token":"<jwt>","expires_at":<unix-seconds>}

# All /v1 requests require a valid bearer JWT. tenant/provider come from the
# token's claims — the x-tenant-id header is no longer trusted. TOKEN below is a
# JWT minted by your IdP (or the HS256 dev secret above).
H="-H \"Authorization: Bearer $TOKEN\""

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

## Cache backend

The cache is selected at startup from the environment (default: in-memory):

```bash
# Default — process-local in-memory cache. Correct only at a SINGLE instance.
# (unset TAHLK_CACHE_BACKEND)

# Shared Redis cache — REQUIRED before running more than one replica.
export TAHLK_CACHE_BACKEND=redis
export TAHLK_REDIS_URL="redis://redis.internal:6379"   # default 127.0.0.1:6379
cargo run
```

`InMemoryCache` is per-process: once more than one replica runs, instance A can
keep serving a list that instance B has already invalidated (the S4 stale-read
bug). Selecting `redis` moves the cache into shared Redis so an invalidate on
any instance is seen by all. When `TAHLK_CACHE_BACKEND=redis` is set, `main`
connects eagerly and **fails closed** (exits non-zero) if `TAHLK_REDIS_URL` is
unreachable — it never silently degrades to a per-replica cache. Transient Redis
errors *after* startup degrade a single request to "uncached" (the store stays
the source of truth), never to a failed request.

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
for the checklist that gates unfreeze. The auth (S1) and network-defense (S2)
items are **done**; the store/cache swaps are still outstanding.

- **Store → Postgres** (`sqlx`): apply `migrations/0001_init.sql`. Per request,
  `SET app.tenant_id` from the JWT so row-level security enforces isolation at
  the database. Connection pool sized to instance count × pool size.
- **Cache → Redis (S4) — implemented.** `RedisCache` is shared across
  horizontally-scaled instances; the in-memory default is per-process and only
  correct at one replica. Select it with `TAHLK_CACHE_BACKEND=redis` (+
  `TAHLK_REDIS_URL`) — no code change, no rebuild. See
  [Cache backend](#cache-backend). Startup fails closed if the configured Redis
  is unreachable.
- **Auth (S1) — done.** `auth.rs` verifies the token signature against a JWKS
  fetched from the configured issuer (`TAHLK_JWKS_URL`), validates `iss`, `aud`,
  `exp`, `nbf`, requires `tenant_id` / `provider_id` claims, and derives
  `TenantCtx` from those claims — never from headers. Startup fails closed if
  the JWKS is unreachable. Configure via `TAHLK_JWT_ISSUER` /
  `TAHLK_JWT_AUDIENCE` / `TAHLK_JWKS_URL` (see Run).
- **Network defenses (S2) — done.** TLS is still terminated **upstream** (nginx
  / ALB / Cloudflare); this service speaks plain HTTP behind it. In-process it
  now enforces:
  - a 1 MiB request-body cap (`RequestBodyLimitLayer`) so an oversized JSON blob
    can't OOM a replica;
  - a per-tenant rate limiter (100 req/min, keyed on the **verified** tenant via
    `governor`, not the source IP);
  - a fail-closed bind gate: refuses to bind a non-loopback address unless
    `TAHLK_ALLOW_INSECURE=1` is explicitly set, so an accidental deploy without a
    TLS-terminating upstream fails safely at startup. The bind IP itself
    defaults to `127.0.0.1` and is configurable via `TAHLK_BIND_ADDR` (e.g. set
    to `0.0.0.0` in a container behind a reverse proxy, alongside
    `TAHLK_ALLOW_INSECURE=1`).
- **Audio (PHI)**: never transits this service body. Client uploads encrypted
  WAV directly to object storage via a short-lived presigned URL; only the
  object key is stored here.

## Scaling notes

Stateless service → scale horizontally behind a load balancer (HPA on CPU/RPS).
State lives in Postgres (read replicas for list/get) and Redis. The audit table
is append-only and partitioned by month at volume. See the design doc for the
full topology, caching strategy, and HIPAA posture.
