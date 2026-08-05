-- Consolidated database baseline as of 2026-08-05.
-- This branch intentionally supports only this schema; no incremental upgrade path is provided.
-- WARNING: This script DROPs existing tables and data.

PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS send_file_chunks;
DROP TABLE IF EXISTS send_files;
DROP TABLE IF EXISTS sends;
DROP TABLE IF EXISTS notification_outbox;
DROP TABLE IF EXISTS registration_tokens;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS organization_api_key;
DROP TABLE IF EXISTS org_policies;
DROP TABLE IF EXISTS collections_groups;
DROP TABLE IF EXISTS groups_users;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS invitations;
DROP TABLE IF EXISTS folders_ciphers;
DROP TABLE IF EXISTS favorites;
DROP TABLE IF EXISTS ciphers_collections;
DROP TABLE IF EXISTS users_collections;
DROP TABLE IF EXISTS collections;
DROP TABLE IF EXISTS cipher_attachments;
DROP TABLE IF EXISTS archives;
DROP TABLE IF EXISTS ciphers;
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS users_organizations;
DROP TABLE IF EXISTS emergency_access;
DROP TABLE IF EXISTS auth_requests;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS protected_action_otp;
DROP TABLE IF EXISTS two_factor_email;
DROP TABLE IF EXISTS two_factor_external;
DROP TABLE IF EXISTS two_factor_incomplete;
DROP TABLE IF EXISTS twofactor_duo_ctx;
DROP TABLE IF EXISTS two_factor_authenticator;
DROP TABLE IF EXISTS webauthn_challenges;
DROP TABLE IF EXISTS two_factor_webauthn_settings;
DROP TABLE IF EXISTS two_factor_webauthn;
DROP TABLE IF EXISTS two_factor_keys;
DROP TABLE IF EXISTS jwt_keys;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS users;
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT 0,
    avatar_color TEXT,
    master_password_hash TEXT NOT NULL,
    master_password_hint TEXT,
    key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    kdf_type INTEGER NOT NULL DEFAULT 1,
    kdf_iterations INTEGER NOT NULL DEFAULT 3,
    kdf_memory INTEGER DEFAULT 64,
    kdf_parallelism INTEGER DEFAULT 4,
    security_stamp TEXT,
    password_salt TEXT,
    password_iterations INTEGER NOT NULL DEFAULT 600000,
    api_key TEXT,
    email_new TEXT,
    email_new_token TEXT,
    email_new_token_sent_at TEXT,
    totp_recover TEXT,
    equivalent_domains TEXT NOT NULL DEFAULT '[]',
    excluded_globals TEXT NOT NULL DEFAULT '[]',
    ua_history TEXT DEFAULT '{"records":[]}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

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

CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ciphers (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT,
    organization_id TEXT,
    type INTEGER NOT NULL,
    data TEXT NOT NULL,
    key TEXT,
    favorite BOOLEAN NOT NULL DEFAULT 0,
    folder_id TEXT,
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS archives (
    user_id TEXT NOT NULL,
    cipher_id TEXT NOT NULL,
    archived_at TEXT NOT NULL,
    PRIMARY KEY (user_id, cipher_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cipher_attachments (
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

CREATE TABLE IF NOT EXISTS ciphers_collections (
    cipher_id TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    PRIMARY KEY (cipher_id, collection_id),
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
    FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE
);

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
    api_key TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS sends (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    organization_id TEXT,
    type INTEGER NOT NULL,
    name TEXT NOT NULL,
    notes TEXT,
    data TEXT NOT NULL,
    key TEXT NOT NULL,
    password_hash TEXT,
    password_salt TEXT,
    password_iter INTEGER,
    max_access_count INTEGER,
    access_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expiration_date TEXT,
    deletion_date TEXT NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT 0,
    hide_email BOOLEAN,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS send_files (
    id TEXT PRIMARY KEY NOT NULL,
    send_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime TEXT,
    data_base64 TEXT,
    r2_object_key TEXT,
    storage_type TEXT NOT NULL DEFAULT 'd1_base64',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (send_id) REFERENCES sends(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS send_file_chunks (
    send_file_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    data_base64 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (send_file_id, chunk_index),
    FOREIGN KEY (send_file_id) REFERENCES send_files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS two_factor_authenticator (
    user_id TEXT PRIMARY KEY NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    secret_enc TEXT NOT NULL,
    last_used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS two_factor_external (
    user_id TEXT NOT NULL,
    type INTEGER NOT NULL CHECK (type IN (2, 3)),
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, type),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

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

CREATE TABLE IF NOT EXISTS twofactor_duo_ctx (
    state TEXT PRIMARY KEY NOT NULL,
    user_email TEXT NOT NULL,
    nonce TEXT NOT NULL,
    exp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS two_factor_email (
    user_id TEXT PRIMARY KEY NOT NULL,
    atype INTEGER NOT NULL DEFAULT 1,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS two_factor_webauthn (
    user_id TEXT NOT NULL,
    slot_id INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    credential_id_b64url TEXT NOT NULL,
    public_key_cose_b64 TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    prf_status INTEGER NOT NULL DEFAULT 2,
    encrypted_public_key TEXT,
    encrypted_user_key TEXT,
    encrypted_private_key TEXT,
    credential_use TEXT NOT NULL DEFAULT 'both',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, slot_id),
    UNIQUE (user_id, credential_id_b64url),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS two_factor_webauthn_settings (
    user_id TEXT PRIMARY KEY NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    user_id TEXT PRIMARY KEY NOT NULL,
    challenge_b64url TEXT NOT NULL,
    challenge_type TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    device_identifier TEXT NOT NULL,
    device_name TEXT,
    device_type INTEGER,
    remember_token_hash TEXT,
    refresh_token TEXT,
    push_token TEXT,
    push_uuid TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, device_identifier),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_requests (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    request_device_identifier TEXT NOT NULL,
    device_type INTEGER NOT NULL,
    request_ip TEXT NOT NULL,
    response_device_identifier TEXT,
    access_code_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    enc_key TEXT,
    master_password_hash TEXT,
    approved INTEGER,
    creation_date TEXT NOT NULL,
    response_date TEXT,
    authentication_date TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS protected_action_otp (
    user_id TEXT PRIMARY KEY NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

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

CREATE TABLE IF NOT EXISTS jwt_keys (
    id TEXT PRIMARY KEY NOT NULL DEFAULT 'global',
    access_secret TEXT NOT NULL,
    refresh_secret TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS two_factor_keys (
    id TEXT PRIMARY KEY NOT NULL DEFAULT 'global',
    key_b64 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ciphers_user_id ON ciphers(user_id);
CREATE INDEX IF NOT EXISTS idx_ciphers_folder_id ON ciphers(folder_id);
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
CREATE INDEX IF NOT EXISTS idx_archives_user_id ON archives(user_id);
CREATE INDEX IF NOT EXISTS idx_archives_cipher_id ON archives(cipher_id);
CREATE INDEX IF NOT EXISTS idx_cipher_attachments_cipher ON cipher_attachments(cipher_id);
CREATE INDEX IF NOT EXISTS idx_cipher_attachments_user ON cipher_attachments(user_id);
CREATE INDEX IF NOT EXISTS idx_sends_user_id ON sends(user_id);
CREATE INDEX IF NOT EXISTS idx_sends_deletion_date ON sends(deletion_date);
CREATE INDEX IF NOT EXISTS idx_send_files_send_id ON send_files(send_id);
CREATE INDEX IF NOT EXISTS idx_send_file_chunks_send_file_id ON send_file_chunks(send_file_id);
CREATE INDEX IF NOT EXISTS idx_folders_user_id ON folders(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_push_uuid ON devices(push_uuid);
CREATE INDEX IF NOT EXISTS idx_auth_requests_user_id ON auth_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_protected_action_otp_user_id ON protected_action_otp(user_id);
CREATE INDEX IF NOT EXISTS idx_two_factor_external_user ON two_factor_external(user_id);
CREATE INDEX IF NOT EXISTS idx_two_factor_incomplete_time ON two_factor_incomplete(login_time);
CREATE INDEX IF NOT EXISTS idx_twofactor_duo_ctx_exp ON twofactor_duo_ctx(exp);
CREATE INDEX IF NOT EXISTS idx_two_factor_webauthn_user_id ON two_factor_webauthn(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_emergency_grantor ON emergency_access(grantor_uuid);
CREATE INDEX IF NOT EXISTS idx_emergency_grantee ON emergency_access(grantee_uuid);
CREATE INDEX IF NOT EXISTS idx_emergency_email ON emergency_access(email, status);
CREATE INDEX IF NOT EXISTS idx_emergency_recovery ON emergency_access(status, recovery_initiated_at);
