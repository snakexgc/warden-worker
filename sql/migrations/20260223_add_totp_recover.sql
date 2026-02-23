-- Add totp_recover column to users table for two-factor recovery code support
ALTER TABLE users ADD COLUMN totp_recover TEXT;
