-- +goose Up

-- Personal API tokens for the account API (/api/v1). They are separate from
-- remoteStorage app tokens and never work on /storage/.
CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hash         BLOB NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL DEFAULT 0,
    expires_at   INTEGER NOT NULL DEFAULT 0  -- 0 = no expiry
);
CREATE INDEX api_tokens_by_user ON api_tokens (user_id);

-- Admin status from OIDC groups, refreshed at every login, so API tokens
-- carry the same rights as the web session.
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE users DROP COLUMN is_admin;
DROP TABLE api_tokens;
