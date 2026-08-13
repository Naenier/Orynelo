ALTER TABLE profiles
    ADD COLUMN mode TEXT NOT NULL DEFAULT 'auto'
    CHECK (mode IN ('auto', 'tcp', 'tls'));
UPDATE profiles SET mode = 'tls' WHERE enable_tls = 1;
UPDATE metadata SET value = '3' WHERE key = 'schema_version';
PRAGMA user_version = 3;
