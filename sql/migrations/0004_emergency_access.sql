-- Vaultwarden-compatible emergency access state.

CREATE TABLE IF NOT EXISTS emergency_access (
    id TEXT PRIMARY KEY NOT NULL,
    grantor_uuid TEXT NOT NULL,
    grantee_uuid TEXT,
    email TEXT,
    key_encrypted TEXT,
    type INTEGER NOT NULL CHECK (type IN (0, 1)),
    status INTEGER NOT NULL CHECK (status BETWEEN 0 AND 4),
    wait_time_days INTEGER NOT NULL,
    recovery_initiated_at TEXT,
    last_notification_at TEXT,
    updated_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (grantor_uuid) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (grantee_uuid) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_emergency_grantor ON emergency_access(grantor_uuid);
CREATE INDEX IF NOT EXISTS idx_emergency_grantee ON emergency_access(grantee_uuid);
CREATE INDEX IF NOT EXISTS idx_emergency_email ON emergency_access(email, status);
CREATE INDEX IF NOT EXISTS idx_emergency_recovery ON emergency_access(status, recovery_initiated_at);
