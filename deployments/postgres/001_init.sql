-- Target schema for M9. The current Go implementation still uses the file store.
CREATE TABLE IF NOT EXISTS runs (
    id                  text PRIMARY KEY,
    tenant_id           text NOT NULL,
    request_id          text NOT NULL,
    agent_id            text NOT NULL,
    agent_display_name  text NOT NULL,
    mode                text NOT NULL,
    status              text NOT NULL,
    version             bigint NOT NULL DEFAULT 1,
    request_json        jsonb NOT NULL,
    result_json         jsonb,
    executor_name       text,
    external_run_id     text,
    sandbox_id          text,
    created_at          timestamptz NOT NULL,
    updated_at          timestamptz NOT NULL,
    started_at          timestamptz,
    finished_at         timestamptz,
    CONSTRAINT runs_tenant_request_unique UNIQUE (tenant_id, request_id)
);

CREATE INDEX IF NOT EXISTS runs_tenant_created_idx ON runs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS runs_status_created_idx ON runs (status, created_at);
CREATE INDEX IF NOT EXISTS runs_agent_created_idx ON runs (tenant_id, agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS run_events (
    sequence_id bigserial PRIMARY KEY,
    event_id    text NOT NULL UNIQUE,
    run_id      text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    tenant_id   text NOT NULL,
    event_type  text NOT NULL,
    actor       text NOT NULL,
    message     text NOT NULL,
    data_json   jsonb,
    created_at  timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS run_events_run_idx ON run_events (run_id, sequence_id);
CREATE INDEX IF NOT EXISTS run_events_tenant_time_idx ON run_events (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id text PRIMARY KEY,
    run_id      text NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
    tenant_id   text NOT NULL,
    actor       text NOT NULL,
    reason      text NOT NULL,
    scope_hash  text NOT NULL,
    created_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    revoked_by  text,
    revoke_reason text
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id text PRIMARY KEY,
    run_id      text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    tenant_id   text NOT NULL,
    name        text NOT NULL,
    media_type  text NOT NULL,
    size_bytes  bigint NOT NULL CHECK (size_bytes >= 0),
    sha256      text NOT NULL,
    storage_uri text NOT NULL,
    classification text NOT NULL DEFAULT 'internal',
    created_at  timestamptz NOT NULL,
    deleted_at  timestamptz
);

CREATE INDEX IF NOT EXISTS artifacts_run_idx ON artifacts (run_id, created_at);
CREATE INDEX IF NOT EXISTS artifacts_hash_idx ON artifacts (tenant_id, sha256);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id text PRIMARY KEY,
    run_id      text NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
    tenant_id   text NOT NULL,
    source_type text NOT NULL,
    source_uri  text NOT NULL,
    source_sha256 text,
    observed_at timestamptz,
    collected_at timestamptz NOT NULL,
    tool_name   text,
    tool_version text,
    operation_json jsonb,
    excerpt     text,
    artifact_ids text[] NOT NULL DEFAULT '{}',
    metadata_json jsonb,
    created_at  timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS evidence_run_idx ON evidence (run_id, created_at);
CREATE INDEX IF NOT EXISTS evidence_tenant_observed_idx ON evidence (tenant_id, observed_at);

CREATE TABLE IF NOT EXISTS findings (
    finding_id text PRIMARY KEY,
    run_id     text NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
    tenant_id  text NOT NULL,
    finding_type text NOT NULL,
    title       text NOT NULL,
    severity    text NOT NULL,
    confidence  numeric(5,4),
    status      text NOT NULL,
    evidence_ids text[] NOT NULL,
    payload_json jsonb NOT NULL,
    created_at  timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS findings_run_idx ON findings (run_id, created_at);
CREATE INDEX IF NOT EXISTS findings_tenant_severity_idx ON findings (tenant_id, severity, created_at DESC);

-- Queue leases allow multiple workers without duplicate execution.
CREATE TABLE IF NOT EXISTS run_leases (
    run_id          text PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    worker_id       text NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    heartbeat_at    timestamptz NOT NULL,
    attempt         integer NOT NULL DEFAULT 1
);
