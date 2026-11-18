-- MANUAL ONLY. This script is not part of automatic migrations.
-- Back up the database. Confirm legacy users, vaults, and sessions are empty.
-- This intentionally replaces incompatible email/password authentication.
-- Breaking migration: only run after ensuring legacy accounts and sessions are backed up.
-- Old email/password accounts are intentionally not migrated.
-- With foreign_keys enabled, dropping users requires there be no dependent rows.
-- For a live installation, export and restore Vault ownership explicitly.
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    account_key_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);
