-- Add per-handle replay hash column to isolate noisy handles from shared replay capacity.

ALTER TABLE webhook_nonces
    ADD COLUMN handle_hash BLOB NOT NULL DEFAULT X'00000000000000000000000000000000'
    CHECK (length(handle_hash) = 16);

CREATE INDEX IF NOT EXISTS idx_webhook_nonces_handle_hash
    ON webhook_nonces (handle_hash);
