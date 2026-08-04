-- Organization-management foundation for the Workers port.
-- Keep this migration additive so an existing personal vault remains usable.

PRAGMA foreign_keys = ON;

DROP TRIGGER IF EXISTS users_single_user_before_insert;

CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    billing_email TEXT NOT NULL,
    private_key TEXT,
    public_key TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users_organizations (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    invited_by_email TEXT,
    access_all INTEGER NOT NULL DEFAULT 0 CHECK (access_all IN (0, 1)),
    key TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 0,
    type INTEGER NOT NULL DEFAULT 2 CHECK (type BETWEEN 0 AND 3),
    reset_password_key TEXT,
    external_id TEXT,
    permissions TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (user_id, organization_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collections (
    id TEXT PRIMARY KEY NOT NULL,
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    external_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users_collections (
    membership_id TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    read_only INTEGER NOT NULL DEFAULT 0 CHECK (read_only IN (0, 1)),
    hide_passwords INTEGER NOT NULL DEFAULT 0 CHECK (hide_passwords IN (0, 1)),
    manage INTEGER NOT NULL DEFAULT 0 CHECK (manage IN (0, 1)),
    PRIMARY KEY (membership_id, collection_id),
    FOREIGN KEY (membership_id) REFERENCES users_organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ciphers_collections (
    cipher_id TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    PRIMARY KEY (cipher_id, collection_id),
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
    FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE
);

-- Favorite and folder placement are user-specific for shared organization ciphers.
CREATE TABLE IF NOT EXISTS favorites (
    user_id TEXT NOT NULL,
    cipher_id TEXT NOT NULL,
    PRIMARY KEY (user_id, cipher_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS folders_ciphers (
    folder_id TEXT NOT NULL,
    cipher_id TEXT NOT NULL,
    PRIMARY KEY (folder_id, cipher_id),
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

INSERT OR IGNORE INTO favorites (user_id, cipher_id)
SELECT user_id, id FROM ciphers WHERE user_id IS NOT NULL AND favorite <> 0;

INSERT OR IGNORE INTO folders_ciphers (folder_id, cipher_id)
SELECT folder_id, id FROM ciphers WHERE folder_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS invitations (
    email TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY NOT NULL,
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    access_all INTEGER NOT NULL DEFAULT 0 CHECK (access_all IN (0, 1)),
    external_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS groups_users (
    group_id TEXT NOT NULL,
    membership_id TEXT NOT NULL,
    PRIMARY KEY (group_id, membership_id),
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY (membership_id) REFERENCES users_organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS collections_groups (
    collection_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    read_only INTEGER NOT NULL DEFAULT 0 CHECK (read_only IN (0, 1)),
    hide_passwords INTEGER NOT NULL DEFAULT 0 CHECK (hide_passwords IN (0, 1)),
    manage INTEGER NOT NULL DEFAULT 0 CHECK (manage IN (0, 1)),
    PRIMARY KEY (collection_id, group_id),
    FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS org_policies (
    id TEXT PRIMARY KEY NOT NULL,
    organization_id TEXT NOT NULL,
    type INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    data TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (organization_id, type),
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS organization_api_key (
    id TEXT PRIMARY KEY NOT NULL,
    organization_id TEXT NOT NULL UNIQUE,
    type INTEGER NOT NULL DEFAULT 0,
    api_key_hash TEXT NOT NULL,
    revision_date TEXT NOT NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY NOT NULL,
    type INTEGER NOT NULL,
    user_id TEXT,
    organization_id TEXT,
    cipher_id TEXT,
    collection_id TEXT,
    group_id TEXT,
    membership_id TEXT,
    device_type INTEGER,
    ip_address TEXT,
    acting_user_id TEXT,
    date TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE SET NULL,
    FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE SET NULL,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL,
    FOREIGN KEY (membership_id) REFERENCES users_organizations(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS registration_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_outbox (
    id TEXT PRIMARY KEY NOT NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    sent_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_memberships_user ON users_organizations(user_id, status);
CREATE INDEX IF NOT EXISTS idx_memberships_org ON users_organizations(organization_id, status, type);
CREATE INDEX IF NOT EXISTS idx_collections_org ON collections(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_collections_collection ON users_collections(collection_id);
CREATE INDEX IF NOT EXISTS idx_cipher_collections_collection ON ciphers_collections(collection_id);
CREATE INDEX IF NOT EXISTS idx_cipher_collections_cipher ON ciphers_collections(cipher_id);
CREATE INDEX IF NOT EXISTS idx_favorites_cipher ON favorites(cipher_id);
CREATE INDEX IF NOT EXISTS idx_folders_ciphers_cipher ON folders_ciphers(cipher_id);
CREATE INDEX IF NOT EXISTS idx_groups_org ON groups(organization_id);
CREATE INDEX IF NOT EXISTS idx_groups_users_membership ON groups_users(membership_id);
CREATE INDEX IF NOT EXISTS idx_collections_groups_group ON collections_groups(group_id);
CREATE INDEX IF NOT EXISTS idx_policies_org ON org_policies(organization_id, enabled);
CREATE INDEX IF NOT EXISTS idx_events_org_date ON events(organization_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_events_user_date ON events(user_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_events_cipher_date ON events(cipher_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_registration_tokens_email ON registration_tokens(email, expires_at);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON notification_outbox(sent_at, next_attempt_at);
