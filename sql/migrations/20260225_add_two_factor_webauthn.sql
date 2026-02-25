PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS two_factor_webauthn (
    user_id TEXT PRIMARY KEY NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS two_factor_webauthn_challenges (
    user_id TEXT NOT NULL,
    atype INTEGER NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, atype),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_two_factor_webauthn_challenges_user
    ON two_factor_webauthn_challenges(user_id);
