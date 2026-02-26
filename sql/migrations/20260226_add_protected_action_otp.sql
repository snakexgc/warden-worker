-- Migration: add protected_action_otp table for account protected actions (request-otp / verify-otp)
CREATE TABLE IF NOT EXISTS protected_action_otp (
    user_id TEXT PRIMARY KEY NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_protected_action_otp_user_id
    ON protected_action_otp(user_id);
