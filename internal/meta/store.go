// Package meta is the metadata store: users, the document tree, OAuth grants
// and tokens. It uses database/sql with SQLite and goose migrations.
package meta

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

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store is the metadata store.
type Store struct {
	// db is for reads. It allows many connections (WAL readers do not block).
	db *sql.DB
	// wdb is for writes. One connection, so writers queue in Go instead of
	// failing with SQLITE_BUSY.
	wdb *sql.DB
}

// Open opens (creating if needed) the SQLite database at path and applies migrations.
func Open(ctx context.Context, path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	dsn := func(txlock string) string {
		q := url.Values{}
		for _, p := range []string{"journal_mode(WAL)", "synchronous(NORMAL)", "foreign_keys(ON)", "busy_timeout(10000)"} {
			q.Add("_pragma", p)
		}
		q.Set("_txlock", txlock)
		return "file:" + path + "?" + q.Encode()
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
	return errors.Join(s.db.Close(), s.wdb.Close())
}

// write runs fn in a write transaction.
func (s *Store) write(ctx context.Context, fn func(tx *sql.Tx) error) error {
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

// User is an account, created on first login.
type User struct {
	ID         int64
	Sub        string
	Username   string
	Email      string
	QuotaBytes int64
	UsedBytes  int64
	CreatedAt  time.Time
	LastLogin  time.Time
	// IsAdmin reflects the OIDC groups at the last login.
	IsAdmin bool
}

const userCols = `id, sub, username, email, quota_bytes, used_bytes, created_at, last_login, is_admin`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created, login int64
	if err := row.Scan(&u.ID, &u.Sub, &u.Username, &u.Email, &u.QuotaBytes, &u.UsedBytes, &created, &login, &u.IsAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.CreatedAt, u.LastLogin = time.Unix(created, 0), time.Unix(login, 0)
	return &u, nil
}

// ErrUsernameTaken is returned when another account already uses the username.
var ErrUsernameTaken = errors.New("username is used by another account")

// Login is what an OIDC login tells us about a user.
type Login struct {
	Sub, Username, Email string
	IsAdmin              bool
}

// UpsertUser records a login. Accounts are keyed by OIDC subject; the
// username is updated if it changed and is still free.
func (s *Store) UpsertUser(ctx context.Context, l Login) (*User, error) {
	var u *User
	err := s.write(ctx, func(tx *sql.Tx) error {
		var owner string
		err := tx.QueryRowContext(ctx, `SELECT sub FROM users WHERE username = ?`, l.Username).Scan(&owner)
		if err == nil && owner != l.Sub {
			return ErrUsernameTaken
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		t := now()
		_, err = tx.ExecContext(ctx, `
			INSERT INTO users (sub, username, email, created_at, last_login, is_admin) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (sub) DO UPDATE SET username = excluded.username, email = excluded.email,
				last_login = excluded.last_login, is_admin = excluded.is_admin`,
			l.Sub, l.Username, l.Email, t, t, l.IsAdmin)
		if err != nil {
			return err
		}
		u, err = scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE sub = ?`, l.Sub))
		return err
	})
	return u, err
}

// UserByName returns the user with the given storage username.
func (s *Store) UserByName(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, username))
}

// UserByID returns a user by id.
func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// ListUsers returns all users ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetQuota sets a user's quota in bytes (0 = server default).
func (s *Store) SetQuota(ctx context.Context, userID, quota int64) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE users SET quota_bytes = ? WHERE id = ?`, quota, userID)
		return err
	})
}
