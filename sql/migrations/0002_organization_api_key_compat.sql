-- Store organization API keys using Vaultwarden's organization_api_key model.
-- 0001 used api_key_hash for a feature that was not yet wired to any endpoint;
-- no key could have been created by the application before this migration.

ALTER TABLE organization_api_key RENAME COLUMN api_key_hash TO api_key;
