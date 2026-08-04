-- Vaultwarden-compatible storage for Duo (2) and YubiKey OTP (3).

CREATE TABLE IF NOT EXISTS two_factor_external (
    user_id TEXT NOT NULL,
    type INTEGER NOT NULL CHECK (type IN (2, 3)),
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, type),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_two_factor_external_user
    ON two_factor_external(user_id);
