ALTER TABLE upstream_keys ADD COLUMN IF NOT EXISTS model_scope TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_upstream_keys_provider_scope ON upstream_keys(provider, model_scope) WHERE status = 'active';
