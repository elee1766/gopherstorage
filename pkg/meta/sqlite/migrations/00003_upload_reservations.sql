-- +goose Up

-- Existing pending blobs predate durable byte accounting. Mark them unknown so
-- upload admission fails closed until GC deletes them and releases their debt.
ALTER TABLE pending_blobs ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT -1 CHECK (size_bytes >= -1);

-- A reservation and its pending blob are created in one writer transaction.
-- The unique path key prevents simultaneous replacements from both crediting
-- the same current document size against quota.
CREATE TABLE upload_reservations (
    blob_key       TEXT PRIMARY KEY REFERENCES pending_blobs(blob_key) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    path           TEXT NOT NULL,
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes >= 0),
    credit_bytes   INTEGER NOT NULL CHECK (credit_bytes >= 0),
    orphan_bytes   INTEGER NOT NULL CHECK (orphan_bytes >= 0),
    created_at     INTEGER NOT NULL,
    UNIQUE (user_id, path)
) WITHOUT ROWID;
CREATE INDEX upload_reservations_by_user ON upload_reservations (user_id, created_at);
CREATE INDEX upload_reservations_by_created ON upload_reservations (created_at);

-- +goose Down
DROP TABLE upload_reservations;
ALTER TABLE pending_blobs DROP COLUMN size_bytes;
