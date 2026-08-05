-- Persist mobile push registration data used by Vaultwarden's push relay.

ALTER TABLE devices ADD COLUMN push_token TEXT;
ALTER TABLE devices ADD COLUMN push_uuid TEXT;

CREATE INDEX IF NOT EXISTS idx_devices_push_uuid ON devices(push_uuid);
