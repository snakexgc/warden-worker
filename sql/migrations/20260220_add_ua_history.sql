-- Add ua_history column to users table for tracking recent user agents
ALTER TABLE users ADD COLUMN ua_history TEXT DEFAULT '{"records":[]}';
