package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
	"github.com/elee1766/gopherstorage/pkg/meta"
)

const nodeCols = `path, is_folder, etag, content_type, size, blob_key, modified_at`

type scanner interface{ Scan(...any) error }

func scanNode(row scanner) (*meta.Node, error) {
	var n meta.Node
	var folder int
	var mod int64
	if err := row.Scan(&n.Path, &folder, &n.ETag, &n.ContentType, &n.Size, &n.BlobKey, &mod); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, meta.ErrNotFound
		}
		return nil, err
	}
	n.IsFolder = folder == 1
	n.Modified = time.Unix(mod, 0).UTC()
	return &n, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func getNode(ctx context.Context, q querier, userID int64, path string) (*meta.Node, error) {
	return scanNode(q.QueryRowContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE user_id = ? AND path = ?`, userID, path))
}

// GetNode returns a document or folder. Missing items return meta.ErrNotFound.
func (s *Store) GetNode(ctx context.Context, userID int64, path string) (*meta.Node, error) {
	return getNode(ctx, s.db, userID, path)
}

// ListFolder returns the folder node and its direct children, sorted by path.
// A folder that does not exist returns (nil, nil, nil).
func (s *Store) ListFolder(ctx context.Context, userID int64, folder string) (*meta.Node, []*meta.Node, error) {
	return s.ListFolderLimit(ctx, userID, folder, 10_000)
}

// ListFolderLimit returns at most limit direct children. If more children exist,
// it returns rs.ErrTooLarge rather than a partial listing.
func (s *Store) ListFolderLimit(ctx context.Context, userID int64, folder string, limit int) (*meta.Node, []*meta.Node, error) {
	if limit <= 0 {
		limit = 10_000
	} else if limit > 100_000 {
		limit = 100_000
	}
	// Read the folder and its children from one snapshot.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	f, err := getNode(ctx, tx, userID, folder)
	if errors.Is(err, meta.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+nodeCols+` FROM nodes WHERE user_id = ? AND parent = ? ORDER BY path LIMIT ?`, userID, folder, limit+1)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var children []*meta.Node
	for rows.Next() {
		if len(children) == limit {
			return nil, nil, rs.ErrTooLarge
		}
		n, err := scanNode(rows)
		if err != nil {
			return nil, nil, err
		}
		children = append(children, n)
	}
	return f, children, rows.Err()
}

func newETag() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func parentOf(p string) any {
	if pp := rs.ParentPath(p); pp != "" {
		return pp
	}
	return nil
}

func checkNewNodeChildren(ctx context.Context, tx *sql.Tx, userID int64, path string, exists bool, limit int) error {
	if exists || limit <= 0 {
		return nil
	}
	checkParent := func(parent any) error {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE user_id = ? AND parent IS ?`, userID, parent).Scan(&count); err != nil {
			return err
		}
		if count >= limit {
			return rs.ErrTooLarge
		}
		return nil
	}
	for dir := rs.ParentPath(path); dir != ""; dir = rs.ParentPath(dir) {
		if _, err := getNode(ctx, tx, userID, dir); !errors.Is(err, meta.ErrNotFound) {
			if err != nil {
				return err
			}
			continue
		}
		if err := checkParent(parentOf(dir)); err != nil {
			return err
		}
	}
	return checkParent(parentOf(path))
}

// touchAncestors gives every ancestor folder of path a new ETag, creating
// folders that do not exist yet.
func touchAncestors(ctx context.Context, tx *sql.Tx, userID int64, path string, t int64) error {
	for dir := rs.ParentPath(path); dir != ""; dir = rs.ParentPath(dir) {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO nodes (user_id, path, parent, is_folder, etag, modified_at) VALUES (?, ?, ?, 1, ?, ?)
			ON CONFLICT (user_id, path) DO UPDATE SET etag = excluded.etag, modified_at = excluded.modified_at`,
			userID, dir, parentOf(dir), newETag(), t)
		if err != nil {
			return err
		}
	}
	return nil
}

// meta.PutDocument creates or replaces a document, checking conditions, name
// conflicts and quota, and updates all ancestor folder ETags atomically.
// The new blob must already be stored and registered with AddPendingBlob.
func (s *Store) PutDocument(ctx context.Context, in meta.PutDocument) (*meta.PutResult, error) {
	if len(in.Path) > 4096 || strings.Count(in.Path, "/") > 65 {
		return nil, rs.ErrTooLarge
	}
	var res meta.PutResult
	err := s.write(ctx, func(tx *sql.Tx) error {
		var disabled bool
		if err := tx.QueryRowContext(ctx, `SELECT disabled FROM users WHERE id = ?`, in.UserID).Scan(&disabled); err != nil {
			return err
		}
		if disabled {
			return meta.ErrAccountDisabled
		}
		old, err := getNode(ctx, tx, in.UserID, in.Path)
		if err != nil && !errors.Is(err, meta.ErrNotFound) {
			return err
		}
		exists := old != nil && !old.IsFolder
		var cur string
		if exists {
			cur = old.ETag
		}
		if err := in.Cond.Check(exists, cur); err != nil {
			return err
		}
		if err := checkNewNodeChildren(ctx, tx, in.UserID, in.Path, exists, in.MaxFolderChildren); err != nil {
			return err
		}
		// A folder with this name, or a document on the ancestor path, conflicts.
		if _, err := getNode(ctx, tx, in.UserID, in.Path+"/"); err == nil {
			return rs.ErrConflict
		} else if !errors.Is(err, meta.ErrNotFound) {
			return err
		}
		for dir := rs.ParentPath(in.Path); dir != "/" && dir != ""; dir = rs.ParentPath(dir) {
			n, err := getNode(ctx, tx, in.UserID, dir[:len(dir)-1])
			if err == nil && !n.IsFolder {
				return rs.ErrConflict
			}
			if err != nil && !errors.Is(err, meta.ErrNotFound) {
				return err
			}
		}
		var oldSize int64
		if exists {
			oldSize = old.Size
			res.OldBlobKey = old.BlobKey
		}
		if err := consumeUploadReservation(ctx, tx, in.UserID, in.Path, in.BlobKey, in.Size); err != nil {
			return err
		}
		if in.MaxNodes > 0 {
			var count int64
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE user_id = ?`, in.UserID).Scan(&count); err != nil {
				return err
			}
			missing := int64(0)
			for dir := rs.ParentPath(in.Path); dir != ""; dir = rs.ParentPath(dir) {
				if _, err := getNode(ctx, tx, in.UserID, dir); errors.Is(err, meta.ErrNotFound) {
					missing++
				} else if err != nil {
					return err
				}
			}
			newDocument := int64(0)
			if !exists {
				newDocument = 1
			}
			if count+missing+newDocument > in.MaxNodes {
				return rs.ErrTooLarge
			}
		}
		delta := in.Size - oldSize
		if in.Quota > 0 && delta > 0 {
			var used int64
			if err := tx.QueryRowContext(ctx, `SELECT used_bytes FROM users WHERE id = ?`, in.UserID).Scan(&used); err != nil {
				return err
			}
			if used >= in.Quota || delta > in.Quota-used {
				return rs.ErrQuotaExceeded
			}
		}
		// A collector claim and publication are serialized by the write lock.
		// Only an unclaimed upload may become referenced by a node.
		claim, err := tx.ExecContext(ctx, `DELETE FROM pending_blobs WHERE blob_key = ? AND reason = 'upload'`, in.BlobKey)
		if err != nil {
			return err
		}
		if n, err := claim.RowsAffected(); err != nil {
			return err
		} else if n != 1 {
			return rs.ErrConflict
		}
		t := now()
		etag := in.ETag
		if etag == "" || etag == cur {
			// Same content as before still gets a new version, so the
			// response ETag always differs from the replaced one.
			etag = newETag()
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO nodes (user_id, path, parent, is_folder, etag, content_type, size, blob_key, modified_at)
			VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?)
			ON CONFLICT (user_id, path) DO UPDATE SET etag = excluded.etag, content_type = excluded.content_type,
				size = excluded.size, blob_key = excluded.blob_key, modified_at = excluded.modified_at`,
			in.UserID, in.Path, parentOf(in.Path), etag, in.ContentType, in.Size, in.BlobKey, t)
		if err != nil {
			return err
		}
		if err := touchAncestors(ctx, tx, in.UserID, in.Path, t); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET used_bytes = used_bytes + ? WHERE id = ?`, delta, in.UserID); err != nil {
			return err
		}
		// The old blob becomes an orphan.
		if res.OldBlobKey != "" && res.OldBlobKey != in.BlobKey {
			if err := addPending(ctx, tx, res.OldBlobKey, "orphan", oldSize); err != nil {
				return err
			}
		}
		res.ETag, res.Created = etag, !exists
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// DeleteDocument removes a document, removes folders left empty and updates
// the ETags of the remaining ancestors.
func (s *Store) DeleteDocument(ctx context.Context, userID int64, path string, cond rsserver.Condition) (*meta.DeleteResult, error) {
	var res meta.DeleteResult
	err := s.write(ctx, func(tx *sql.Tx) error {
		old, err := getNode(ctx, tx, userID, path)
		if err != nil && !errors.Is(err, meta.ErrNotFound) {
			return err
		}
		exists := old != nil && !old.IsFolder
		var cur string
		if exists {
			cur = old.ETag
		}
		if err := cond.Check(exists, cur); err != nil {
			return err
		}
		if !exists {
			return rs.ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE user_id = ? AND path = ?`, userID, path); err != nil {
			return err
		}
		t := now()
		for dir := rs.ParentPath(path); dir != ""; dir = rs.ParentPath(dir) {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM nodes WHERE user_id = ? AND parent = ? LIMIT 1)`, userID, dir).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				if _, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE user_id = ? AND path = ?`, userID, dir); err != nil {
					return err
				}
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE nodes SET etag = ?, modified_at = ? WHERE user_id = ? AND path = ?`, newETag(), t, userID, dir); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET used_bytes = used_bytes - ? WHERE id = ?`, old.Size, userID); err != nil {
			return err
		}
		if old.BlobKey != "" {
			if err := addPending(ctx, tx, old.BlobKey, "orphan", old.Size); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE upload_reservations SET credit_bytes = 0, orphan_bytes = 0 WHERE user_id = ? AND path = ?`, userID, path); err != nil {
			return err
		}
		res.ETag, res.BlobKey = old.ETag, old.BlobKey
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func addPending(ctx context.Context, tx *sql.Tx, key, reason string, sizeBytes int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO pending_blobs (blob_key, reason, created_at, size_bytes) VALUES (?, ?, ?, ?)
		ON CONFLICT (blob_key) DO UPDATE SET reason = excluded.reason, size_bytes = excluded.size_bytes`, key, reason, now(), sizeBytes)
	return err
}

// AddPendingBlob records a blob before it is uploaded, so it is collected if
// the upload or the metadata write never completes.
func (s *Store) AddPendingBlob(ctx context.Context, key string) error {
	return s.write(ctx, func(tx *sql.Tx) error { return addPending(ctx, tx, key, "upload", -1) })
}

// CollectableBlobs returns orphans, and uploads older than uploadGrace
// (which belong to requests that died), that no node references.
// A nonpositive grace claims every unreferenced upload and requires an offline caller.
func (s *Store) CollectableBlobs(ctx context.Context, uploadGrace time.Duration, limit int) ([]meta.PendingBlob, error) {
	cutoff := time.Now().Add(-uploadGrace).Unix()
	var out []meta.PendingBlob
	err := s.write(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT p.blob_key, p.reason, p.created_at FROM pending_blobs p
			WHERE (p.reason IN ('orphan', 'collecting') OR (p.reason = 'upload' AND (p.created_at < ? OR ?)))
			  AND NOT EXISTS (SELECT 1 FROM nodes n WHERE n.blob_key = p.blob_key)
			ORDER BY p.created_at LIMIT ?`, cutoff, uploadGrace <= 0, limit)
		if err != nil {
			return err
		}
		for rows.Next() {
			var b meta.PendingBlob
			var t int64
			if err := rows.Scan(&b.Key, &b.Reason, &t); err != nil {
				rows.Close()
				return err
			}
			b.CreatedAt = time.Unix(t, 0)
			out = append(out, b)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		claimed := out[:0]
		for _, b := range out {
			res, err := tx.ExecContext(ctx, `UPDATE pending_blobs SET reason = 'collecting'
				WHERE blob_key = ? AND NOT EXISTS (SELECT 1 FROM nodes n WHERE n.blob_key = pending_blobs.blob_key)`, b.Key)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 1 {
				b.Reason = "collecting"
				claimed = append(claimed, b)
			}
		}
		out = claimed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ForgetBlob removes a pending entry once its blob is gone from the blob store.
func (s *Store) ForgetBlob(ctx context.Context, key string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM pending_blobs WHERE blob_key = ? AND NOT EXISTS (SELECT 1 FROM nodes WHERE blob_key = ?)`, key, key)
		return err
	})
}

// Usage reports the number of documents and bytes of a user.
func (s *Store) Usage(ctx context.Context, userID int64) (docs, bytes int64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM nodes WHERE user_id = ? AND is_folder = 0`, userID).Scan(&docs, &bytes)
	return docs, bytes, err
}

// ListPublic returns up to limit documents under /public/, newest first.
func (s *Store) ListPublic(ctx context.Context, userID int64, limit int) ([]*meta.Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+nodeCols+` FROM nodes
		WHERE user_id = ? AND is_folder = 0 AND path >= '/public/' AND path < '/public0'
		ORDER BY modified_at DESC, path LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*meta.Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
