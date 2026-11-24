-- Initial SQLite schema for pubky-dispatch-push-relay.

CREATE TABLE IF NOT EXISTS registrations (
    handle            TEXT PRIMARY KEY NOT NULL,
    platform          TEXT NOT NULL CHECK (platform IN ('apns', 'fcm')),
    device_token      TEXT NOT NULL,
    push_key          BLOB NOT NULL CHECK (length(push_key) = 32),
    apns_env          TEXT CHECK (apns_env IS NULL OR apns_env IN ('production', 'sandbox')),
    created_at_ms     INTEGER NOT NULL,
    last_active_at_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_registrations_push_key
    ON registrations (push_key);

CREATE INDEX IF NOT EXISTS idx_registrations_last_active
    ON registrations (last_active_at_ms);

CREATE TABLE IF NOT EXISTS webhook_nonces (
    nonce           BLOB PRIMARY KEY NOT NULL CHECK (length(nonce) = 16),
    expires_at_ms   INTEGER NOT NULL,
    boot_id         BLOB NOT NULL CHECK (length(boot_id) = 16),
    mono_expires_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_webhook_nonces_expires_at
    ON webhook_nonces (expires_at_ms);
