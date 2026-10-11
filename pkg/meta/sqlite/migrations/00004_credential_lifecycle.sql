-- +goose Up

ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;

CREATE TABLE sessions (
    id_hash BLOB PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL DEFAULT '',
    oidc_sub TEXT NOT NULL DEFAULT '',
    oidc_sid TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX sessions_by_user ON sessions(user_id);
CREATE INDEX sessions_by_oidc_sid ON sessions(issuer, oidc_sid) WHERE oidc_sid <> '';
CREATE INDEX sessions_by_oidc_sub ON sessions(issuer, oidc_sub) WHERE oidc_sub <> '';
CREATE INDEX sessions_by_expiry ON sessions(expires_at);

CREATE TABLE logout_replays (
    issuer TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (issuer, jti)
) WITHOUT ROWID;
CREATE INDEX logout_replays_by_expiry ON logout_replays(expires_at);

-- +goose Down
DROP TABLE logout_replays;
DROP TABLE sessions;
ALTER TABLE users DROP COLUMN disabled;
