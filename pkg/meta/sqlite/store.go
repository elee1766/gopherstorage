// Package sqlite implements the metadata store using database/sql and goose migrations.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/elee1766/gopherstorage/pkg/meta"
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the metadata store.
type Store struct {
	// db is for reads. It allows many connections (WAL readers do not block).
	db *sql.DB
	// wdb is for writes. One connection, so writers queue in Go instead of
	// failing with SQLITE_BUSY.
	wdb *sql.DB
}

var _ meta.Store = (*Store)(nil)

// Open opens (creating if needed) the SQLite database at path and applies migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	path = abs
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	dsn := func(txlock string) string {
		q := url.Values{}
		for _, p := range []string{"journal_mode(WAL)", "synchronous(NORMAL)", "foreign_keys(ON)", "busy_timeout(10000)"} {
			q.Add("_pragma", p)
		}
		q.Set("_txlock", txlock)
		u := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: q.Encode()}
		return u.String()
	}
	db, err := sql.Open("sqlite", dsn("deferred"))
	if err != nil {
		return nil, err
	}
	wdb, err := sql.Open("sqlite", dsn("immediate"))
	if err != nil {
		db.Close()
		return nil, err
	}
	wdb.SetMaxOpenConns(1)
	s := &Store{db: db, wdb: wdb}
	if err := s.migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, s.wdb, sub)
	if err != nil {
		return err
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	if s.wdb == nil {
		return s.db.Close()
	}
	return errors.Join(s.db.Close(), s.wdb.Close())
}

// write runs fn in a write transaction.
func (s *Store) write(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if s.wdb == nil {
		return meta.ErrReadOnly
	}
	tx, err := s.wdb.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func now() int64 { return time.Now().Unix() }
