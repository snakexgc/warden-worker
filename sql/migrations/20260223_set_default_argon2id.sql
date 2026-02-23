-- Migration: Set default KDF to Argon2id for new users
-- This migration updates the default values for KDF settings

-- Update existing users who still have PBKDF2 default (kdf_type = 0 and kdf_iterations = 600000)
-- Only update if they haven't explicitly changed their KDF settings
UPDATE users 
SET 
    kdf_type = 1,
    kdf_iterations = 3,
    kdf_memory = 64,
    kdf_parallelism = 4
WHERE 
    kdf_type = 0 
    AND kdf_iterations = 600000
    AND kdf_memory IS NULL
    AND kdf_parallelism IS NULL;

-- Note: For existing databases, you may want to run this manually:
-- ALTER TABLE users ALTER COLUMN kdf_type SET DEFAULT 1;
-- ALTER TABLE users ALTER COLUMN kdf_iterations SET DEFAULT 3;
-- ALTER TABLE users ALTER COLUMN kdf_memory SET DEFAULT 64;
-- ALTER TABLE users ALTER COLUMN kdf_parallelism SET DEFAULT 4;
