package meta

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
)

// BlobRef identifies immutable blob bytes needed by a document in a metadata snapshot.
type BlobRef struct {
	Key  string `json:"key"`
	Size int64  `json:"size"`
}

// BlobRefs returns each distinct blob referenced by a document.
func (s *Store) BlobRefs(ctx context.Context) ([]BlobRef, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT blob_key, MIN(size), COUNT(DISTINCT size)
		FROM nodes WHERE is_folder = 0 GROUP BY blob_key ORDER BY blob_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := make([]BlobRef, 0)
	for rows.Next() {
		var ref BlobRef
		var sizes int
		if err := rows.Scan(&ref.Key, &ref.Size, &sizes); err != nil {
			return nil, err
		}
		if sizes != 1 {
			return nil, fmt.Errorf("metadata has inconsistent size for blob %q", ref.Key)
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

// Snapshot writes a consistent SQLite snapshot to a path that does not exist.
// Unless includeCredentials is true, persisted bearer credentials, sessions,
// authorization codes, and logout replay records are deleted from the copy.
func (s *Store) Snapshot(ctx context.Context, destination string, includeCredentials bool) error {
	if s.wdb == nil {
		return ErrReadOnly
	}
	if destination == "" {
		return fmt.Errorf("snapshot destination is empty")
	}
	_, err := s.wdb.ExecContext(ctx, `VACUUM INTO ?`, destination)
	if err != nil {
		return fmt.Errorf("create SQLite snapshot: %w", err)
	}
	if includeCredentials {
		return nil
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	dsn := (&url.URL{Scheme: "file", Path: absolute}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open snapshot for credential scrub: %w", err)
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return errors.Join(fmt.Errorf("connect to snapshot for credential scrub: %w", err), db.Close())
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA secure_delete=ON`); err != nil {
		return errors.Join(fmt.Errorf("enable secure deletion in snapshot: %w", err), conn.Close(), db.Close())
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return errors.Join(fmt.Errorf("begin snapshot credential scrub: %w", err), conn.Close(), db.Close())
	}
	for _, query := range []string{
		`DELETE FROM api_tokens`,
		`DELETE FROM sessions`,
		`DELETE FROM logout_replays`,
		`DELETE FROM auth_codes`,
		`DELETE FROM tokens`,
		`DELETE FROM grants`,
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return errors.Join(fmt.Errorf("scrub snapshot credentials: %w", err), tx.Rollback(), conn.Close(), db.Close())
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.Join(fmt.Errorf("commit snapshot credential scrub: %w", err), conn.Close(), db.Close())
	}
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return errors.Join(fmt.Errorf("compact scrubbed metadata snapshot: %w", err), conn.Close(), db.Close())
	}
	return errors.Join(conn.Close(), db.Close())
}
