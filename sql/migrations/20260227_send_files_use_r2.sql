ALTER TABLE send_files ADD COLUMN r2_object_key TEXT;
ALTER TABLE send_files ADD COLUMN storage_type TEXT NOT NULL DEFAULT 'd1_base64';

UPDATE send_files
SET storage_type = 'r2'
WHERE r2_object_key IS NOT NULL;
