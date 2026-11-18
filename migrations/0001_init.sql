PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    account_key_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);

CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    latest_revision INTEGER NOT NULL DEFAULT 0,
    latest_hash TEXT
);

CREATE INDEX IF NOT EXISTS vaults_user_idx ON vaults(user_id);

CREATE TABLE IF NOT EXISTS vault_revisions (
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    hash TEXT NOT NULL,
    size INTEGER NOT NULL,
    commit_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, revision)
);

CREATE TABLE IF NOT EXISTS vault_chunks (
    vault_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    chunk_index INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (vault_id, revision, chunk_index),
    FOREIGN KEY (vault_id, revision) REFERENCES vault_revisions(vault_id, revision) ON DELETE CASCADE
);
