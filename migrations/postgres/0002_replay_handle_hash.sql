-- Add per-handle replay hash column to isolate noisy handles from shared replay capacity.

ALTER TABLE webhook_nonces
    ADD COLUMN IF NOT EXISTS handle_hash BYTEA NOT NULL DEFAULT '\x00000000000000000000000000000000'::bytea
    CHECK (octet_length(handle_hash) = 16);

CREATE INDEX IF NOT EXISTS idx_webhook_nonces_handle_hash
    ON webhook_nonces (handle_hash);
