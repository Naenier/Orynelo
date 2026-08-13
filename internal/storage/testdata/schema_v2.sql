CREATE TABLE profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    ip_version TEXT NOT NULL,
    timeout_ns INTEGER NOT NULL,
    check_timeout_ns INTEGER NOT NULL,
    no_proxy INTEGER NOT NULL,
    insecure INTEGER NOT NULL,
    enable_tls INTEGER NOT NULL,
    max_redirects INTEGER NOT NULL,
    method TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX profiles_name_idx ON profiles(name COLLATE NOCASE, id);
UPDATE metadata SET value = '2' WHERE key = 'schema_version';
PRAGMA user_version = 2;
