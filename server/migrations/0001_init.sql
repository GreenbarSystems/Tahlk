-- tahlk-sync initial schema (PostgreSQL).
--
-- Multi-tenant by design: every PHI-bearing row carries tenant_id, and
-- row-level security enforces isolation at the database even if application
-- code forgets a WHERE clause (defense in depth). The service sets
--   SET app.tenant_id = '<uuid>'
-- per request/transaction from the authenticated JWT before any query runs.

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid()

CREATE TABLE tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    plan        TEXT NOT NULL DEFAULT 'group',     -- group | practice | enterprise
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE providers (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email        TEXT NOT NULL,
    name         TEXT,
    credentials  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE TABLE encounters (
    id                TEXT NOT NULL,                 -- client-generated id (offline-first)
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id       UUID NOT NULL REFERENCES providers(id),
    encounter_date    DATE NOT NULL,
    patient_alias     TEXT,                          -- pseudonymous label, not raw PHI
    status            TEXT NOT NULL DEFAULT 'draft',
    audio_object_key  TEXT,                          -- pointer into encrypted object storage
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    signed_at         TIMESTAMPTZ,
    signed_hash       TEXT,
    updated_at        BIGINT NOT NULL DEFAULT 0,     -- server clock for last-writer-wins sync
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX enc_tenant_created_idx ON encounters (tenant_id, created_at DESC);
CREATE INDEX enc_tenant_status_idx  ON encounters (tenant_id, status);

-- Append-only tamper-evident audit / hash chain. No UPDATE/DELETE in practice.
CREATE TABLE audit_log (
    seq           BIGSERIAL PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    encounter_id  TEXT NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,                     -- generated | edited | signed | exported
    ts            TIMESTAMPTZ NOT NULL,              -- client event time
    content_hash  TEXT,
    prev_hash     TEXT,
    entry_hash    TEXT,
    received_at   TIMESTAMPTZ NOT NULL DEFAULT now() -- server receipt time
);
CREATE INDEX audit_tenant_enc_idx ON audit_log (tenant_id, encounter_id, seq);

-- ── Row-level security ──────────────────────────────────────────────────────
ALTER TABLE encounters ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log  ENABLE ROW LEVEL SECURITY;
ALTER TABLE providers  ENABLE ROW LEVEL SECURITY;

CREATE POLICY enc_tenant_isolation ON encounters
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY audit_tenant_isolation ON audit_log
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY provider_tenant_isolation ON providers
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
