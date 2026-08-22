ALTER TABLE users
    ADD COLUMN IF NOT EXISTS terra_daily_used BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS terra_daily_reset_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_terra_daily_reset
    ON users(terra_daily_reset_at);
