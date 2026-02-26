-- Migration: Upgrade WebAuthn tables for Passkey login support
-- This migration transforms the old WebAuthn 2FA-only structure to the new
-- structure that supports both 2FA and Passkey login.

PRAGMA foreign_keys = ON;

-- Step 1: Create new two_factor_webauthn table with new schema
CREATE TABLE IF NOT EXISTS two_factor_webauthn_new (
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

-- Step 2: Migrate existing data from old table to new table
-- Old data format: user_id, enabled, data (JSON), created_at, updated_at
-- New format requires extracting credential info from the old JSON data field
-- Since we cannot reliably extract credential_id and public_key from old JSON,
-- we will insert placeholder records that need to be re-registered
INSERT INTO two_factor_webauthn_new (
    user_id, slot_id, name, credential_id_b64url, public_key_cose_b64,
    sign_count, prf_status, encrypted_public_key, encrypted_user_key, encrypted_private_key,
    credential_use, created_at, updated_at
)
SELECT 
    user_id,
    1 as slot_id,
    'Migrated Credential' as name,
    'migrated_' || user_id as credential_id_b64url,
    'migrated' as public_key_cose_b64,
    0 as sign_count,
    2 as prf_status,
    NULL as encrypted_public_key,
    NULL as encrypted_user_key,
    NULL as encrypted_private_key,
    '2fa' as credential_use,
    created_at,
    updated_at
FROM two_factor_webauthn
WHERE enabled = 1;

-- Step 3: Drop old table and rename new table
DROP TABLE IF EXISTS two_factor_webauthn;
ALTER TABLE two_factor_webauthn_new RENAME TO two_factor_webauthn;

-- Step 4: Create index on new table
CREATE INDEX IF NOT EXISTS idx_two_factor_webauthn_user_id ON two_factor_webauthn(user_id);

-- Step 5: Create two_factor_webauthn_settings table for 2FA enablement status
CREATE TABLE IF NOT EXISTS two_factor_webauthn_settings (
    user_id TEXT PRIMARY KEY NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Step 6: Migrate 2FA enabled status from old table
INSERT INTO two_factor_webauthn_settings (user_id, enabled, created_at, updated_at)
SELECT user_id, enabled, created_at, updated_at
FROM two_factor_webauthn
WHERE enabled = 1
ON CONFLICT(user_id) DO UPDATE SET
    enabled = excluded.enabled,
    updated_at = excluded.updated_at;

-- Step 7: Drop old challenges table
DROP TABLE IF EXISTS two_factor_webauthn_challenges;

-- Step 8: Create new webauthn_challenges table for Passkey login
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

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges(user_id);
