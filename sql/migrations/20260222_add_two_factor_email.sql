-- Migration: Add two_factor_email table for Email 2FA support
-- Date: 2026-02-22

CREATE TABLE IF NOT EXISTS two_factor_email (
    user_id TEXT PRIMARY KEY NOT NULL,
    atype INTEGER NOT NULL DEFAULT 1,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
