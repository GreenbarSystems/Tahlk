# tahlk-sync — Group-tier sync service

> ⛔ **FROZEN — not under active development.** Parked per
> [ADR 0001](../docs/adr/0001-freeze-group-tier-and-sync.md). It stays in CI so
> it keeps compiling, but no new work lands here until the unfreeze criteria are
> met (a signed Group customer **and** an audit-safe sync design). Focus is the
> single-user Solo desktop app. Do not extend this without revisiting the ADR.


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

- **Store → Postgres** (`sqlx`): apply `migrations/0001_init.sql`. Per request,
  `SET app.tenant_id` from the JWT so row-level security enforces isolation at
  the database. Connection pool sized to instance count × pool size.
- **Cache → Redis**: shared across horizontally-scaled instances; the in-memory
  cache is per-process and only correct at one replica.
- **Auth**: replace the header/bearer stub in `auth.rs` with JWT verification
  (issuer/audience/expiry/signature); derive tenant_id + provider_id from claims.
- **Audio (PHI)**: never transits this service body. Client uploads encrypted
  WAV directly to object storage via a short-lived presigned URL; only the
  object key is stored here.

## Scaling notes

Stateless service → scale horizontally behind a load balancer (HPA on CPU/RPS).
State lives in Postgres (read replicas for list/get) and Redis. The audit table
is append-only and partitioned by month at volume. See the design doc for the
full topology, caching strategy, and HIPAA posture.
