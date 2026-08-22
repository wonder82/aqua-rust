ALTER TABLE users
    ADD COLUMN IF NOT EXISTS penalty_active BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS penalty_rpm_limit INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS penalty_concurrency_cap INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS penalty_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS penalty_started_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_penalty_active
    ON users(penalty_active)
    WHERE penalty_active = true;

UPDATE users u
SET penalty_active = true,
    penalty_rpm_limit = 10,
    penalty_concurrency_cap = 1,
    penalty_reason = 'appeal_unban_restriction',
    penalty_started_at = COALESCE(u.updated_at, now())
WHERE EXISTS (
    SELECT 1
    FROM audit_logs a
    WHERE a.action = 'amnesty_unban'
      AND a.target_type = 'user'
      AND a.target_id = u.id::text
);
