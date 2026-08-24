-- File: src/migrations/web/001_initial.sql
-- Project: WireGate
-- Author: Thiep Wong
-- Email: thiep.wong@gmail.com
-- Date: 2026-08-24
-- Description: WireGate database migration.

CREATE TABLE users (
    id                   TEXT PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name         TEXT NOT NULL,
    password_hash        TEXT NOT NULL,
    role                 TEXT NOT NULL CHECK (role IN ('admin','operator','viewer','auditor')),
    status               TEXT NOT NULL CHECK (status IN ('active','locked','disabled')),
    failed_login_count   INTEGER NOT NULL DEFAULT 0,
    locked_until_ms      INTEGER,
    password_changed_ms  INTEGER NOT NULL,
    created_at_ms        INTEGER NOT NULL,
    updated_at_ms        INTEGER NOT NULL
);

CREATE TABLE sessions (
    id_hash             BLOB PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_hash           BLOB NOT NULL,
    reauth_until_ms     INTEGER,
    expires_at_ms       INTEGER NOT NULL,
    idle_expires_at_ms  INTEGER NOT NULL,
    last_seen_at_ms     INTEGER NOT NULL,
    source_ip_prefix    TEXT,
    user_agent_hash     BLOB,
    created_at_ms       INTEGER NOT NULL,
    revoked_at_ms       INTEGER
);

CREATE TABLE login_events (
    id                   TEXT PRIMARY KEY,
    user_id              TEXT REFERENCES users(id) ON DELETE SET NULL,
    username_normalized  TEXT NOT NULL,
    result               TEXT NOT NULL,
    source_ip            TEXT,
    request_id           TEXT NOT NULL,
    created_at_ms        INTEGER NOT NULL
);

CREATE TABLE web_audit_events (
    id                TEXT PRIMARY KEY,
    actor_user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
    action            TEXT NOT NULL,
    target_type       TEXT NOT NULL,
    target_id         TEXT,
    request_id        TEXT NOT NULL,
    result            TEXT NOT NULL,
    details_redacted  TEXT,
    created_at_ms     INTEGER NOT NULL
);

CREATE TABLE bootstrap_state (
    singleton_id   INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    token_hash     BLOB NOT NULL,
    expires_at_ms  INTEGER NOT NULL,
    consumed_at_ms INTEGER,
    created_at_ms  INTEGER NOT NULL
);

CREATE INDEX sessions_user_revoked_idx ON sessions(user_id, revoked_at_ms);
CREATE INDEX sessions_expires_idx ON sessions(expires_at_ms);

