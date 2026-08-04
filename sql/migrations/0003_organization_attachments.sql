-- Vaultwarden authorizes attachments through their parent cipher. Allow an
-- organization-owned cipher attachment to have no personal user owner.

CREATE TABLE cipher_attachments_v2 (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    user_id TEXT,
    file_name TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    key TEXT,
    r2_object_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

INSERT INTO cipher_attachments_v2
    (id, cipher_id, user_id, file_name, size, key, r2_object_key, created_at, updated_at)
SELECT id, cipher_id, user_id, file_name, size, key, r2_object_key, created_at, updated_at
FROM cipher_attachments;

DROP TABLE cipher_attachments;
ALTER TABLE cipher_attachments_v2 RENAME TO cipher_attachments;
CREATE INDEX IF NOT EXISTS idx_cipher_attachments_cipher ON cipher_attachments(cipher_id);
CREATE INDEX IF NOT EXISTS idx_cipher_attachments_user ON cipher_attachments(user_id);
