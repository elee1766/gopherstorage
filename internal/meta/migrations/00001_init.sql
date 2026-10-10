-- +goose Up

-- Users are created on first login from OIDC claims.
CREATE TABLE users (
    id          INTEGER PRIMARY KEY,
    sub         TEXT NOT NULL UNIQUE,          -- OIDC subject
    username    TEXT NOT NULL UNIQUE,          -- storage URL segment
    email       TEXT NOT NULL DEFAULT '',
    quota_bytes INTEGER NOT NULL DEFAULT 0,    -- 0 = server default
    used_bytes  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    last_login  INTEGER NOT NULL
);

-- One row per document and per non-empty folder of a user's tree.
-- path is relative to the storage root: "/a/b.txt" or "/a/".
-- parent is the containing folder ("/a/"), NULL for the root folder.
CREATE TABLE nodes (
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    path         TEXT NOT NULL,
    parent       TEXT,
    is_folder    INTEGER NOT NULL,
    etag         TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT '',
    size         INTEGER NOT NULL DEFAULT 0,
    blob_key     TEXT NOT NULL DEFAULT '',
    modified_at  INTEGER NOT NULL,             -- unix seconds
    PRIMARY KEY (user_id, path)
) WITHOUT ROWID;

-- Folder listings: children of a folder.
CREATE INDEX nodes_by_parent ON nodes (user_id, parent);
-- Blob garbage collection and integrity checks.
CREATE INDEX nodes_by_blob ON nodes (blob_key) WHERE blob_key <> '';

-- Blobs that were written but are not yet (or no longer) referenced.
-- A blob is recorded here before upload, and removed once it is referenced
-- by a node or deleted from the blob store, so crashes never leak blobs.
CREATE TABLE pending_blobs (
    blob_key   TEXT PRIMARY KEY,
    reason     TEXT NOT NULL,                  -- 'upload' or 'orphan'
    created_at INTEGER NOT NULL
) WITHOUT ROWID;

-- Apps authorized by a user (OAuth clients are identified by redirect origin).
CREATE TABLE grants (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id    TEXT NOT NULL,                -- origin of redirect_uri
    client_name  TEXT NOT NULL DEFAULT '',
    scope        TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL DEFAULT 0,
    UNIQUE (user_id, client_id)
);

-- Bearer tokens. Only a SHA-256 hash of the token is stored.
CREATE TABLE tokens (
    hash       BLOB PRIMARY KEY,
    grant_id   INTEGER NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    scope      TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL                -- 0 = no expiry
) WITHOUT ROWID;
CREATE INDEX tokens_by_grant ON tokens (grant_id);
CREATE INDEX tokens_by_expiry ON tokens (expires_at) WHERE expires_at > 0;

-- One-time authorization codes of the PKCE flow.
CREATE TABLE auth_codes (
    hash           BLOB PRIMARY KEY,
    grant_id       INTEGER NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    scope          TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    expires_at     INTEGER NOT NULL
) WITHOUT ROWID;

-- +goose Down
DROP TABLE auth_codes;
DROP TABLE tokens;
DROP TABLE grants;
DROP TABLE pending_blobs;
DROP TABLE nodes;
DROP TABLE users;
