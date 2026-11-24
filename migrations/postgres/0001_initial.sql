-- Initial durable PostgreSQL schema for pubky-dispatch-push-relay.

CREATE TABLE IF NOT EXISTS registrations (
    handle            TEXT PRIMARY KEY NOT NULL,
    platform          TEXT NOT NULL CHECK (platform IN ('apns', 'fcm')),
    device_token      TEXT NOT NULL,
    push_key          BYTEA NOT NULL CHECK (octet_length(push_key) = 32),
    apns_env          TEXT CHECK (apns_env IS NULL OR apns_env IN ('production', 'sandbox')),
    created_at_ms     BIGINT NOT NULL,
    last_active_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registrations_push_key
    ON registrations (push_key);

CREATE INDEX IF NOT EXISTS idx_registrations_last_active
    ON registrations (last_active_at_ms);

-- Durable WAL-logged replay table so crashes and failovers preserve live nonces.
CREATE TABLE IF NOT EXISTS webhook_nonces (
    nonce         BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(nonce) = 16),
    expires_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webhook_nonces_expires_at
    ON webhook_nonces (expires_at_ms);

-- Durable WAL-logged sliding-window rate-limit buckets shared across replicas.
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    scope         TEXT NOT NULL,
    bucket_key    TEXT NOT NULL,
    timestamps    BIGINT[] NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    PRIMARY KEY (scope, bucket_key)
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_expires_at
    ON rate_limit_buckets (expires_at_ms);
