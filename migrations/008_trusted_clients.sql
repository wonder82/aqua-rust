CREATE TABLE IF NOT EXISTS trusted_clients (
    client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    reason TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_trusted_clients_created_at ON trusted_clients(created_at);
