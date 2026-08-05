-- Track password logins that do not complete their second factor in time.

CREATE TABLE IF NOT EXISTS two_factor_incomplete (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    device_type INTEGER NOT NULL,
    login_time TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_two_factor_incomplete_time
    ON two_factor_incomplete(login_time);
