package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/elee1766/gopherstorage/pkg/meta"
)

const userCols = `id, sub, username, email, quota_bytes, used_bytes, created_at, last_login, is_admin, disabled`

func scanUser(row interface{ Scan(...any) error }) (*meta.User, error) {
	var u meta.User
	var created, login int64
	var disabled bool
	if err := row.Scan(&u.ID, &u.Sub, &u.Username, &u.Email, &u.QuotaBytes, &u.UsedBytes, &created, &login, &u.IsAdmin, &disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, meta.ErrNotFound
		}
		return nil, err
	}
	u.CreatedAt, u.LastLogin, u.Disabled = time.Unix(created, 0), time.Unix(login, 0), disabled
	return &u, nil
}

// UpsertUser records a login. Accounts are keyed by OIDC subject. The username may change when it remains available.
func (s *Store) UpsertUser(ctx context.Context, l meta.Login) (*meta.User, error) {
	var u *meta.User
	err := s.write(ctx, func(tx *sql.Tx) error {
		var owner string
		err := tx.QueryRowContext(ctx, `SELECT sub FROM users WHERE username = ?`, l.Username).Scan(&owner)
		if err == nil && owner != l.Sub {
			return meta.ErrUsernameTaken
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		t := now()
		_, err = tx.ExecContext(ctx, `
			INSERT INTO users (sub, username, email, created_at, last_login, is_admin) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (sub) DO UPDATE SET username = excluded.username, email = excluded.email,
				last_login = excluded.last_login, is_admin = excluded.is_admin
			WHERE users.disabled = 0`,
			l.Sub, l.Username, l.Email, t, t, l.IsAdmin)
		if err != nil {
			return err
		}
		var disabled bool
		if err := tx.QueryRowContext(ctx, `SELECT disabled FROM users WHERE sub=?`, l.Sub).Scan(&disabled); err != nil {
			return err
		}
		if disabled {
			return meta.ErrAccountDisabled
		}
		u, err = scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE sub = ?`, l.Sub))
		return err
	})
	return u, err
}

// UserByName returns the user with the given storage username.
func (s *Store) UserByName(ctx context.Context, username string) (*meta.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, username))
}

// UserByID returns a user by ID.
func (s *Store) UserByID(ctx context.Context, id int64) (*meta.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// UserBySub returns a user by OIDC subject.
func (s *Store) UserBySub(ctx context.Context, sub string) (*meta.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE sub = ?`, sub))
}

// ListUsers returns all users ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]*meta.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*meta.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetQuota sets a user's quota in bytes. A quota of 0 means use the server default.
func (s *Store) SetQuota(ctx context.Context, userID, quota int64) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE users SET quota_bytes = ? WHERE id = ?`, quota, userID)
		return err
	})
}
