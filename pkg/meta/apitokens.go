package meta

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const MaxAPITokens = 50

var ErrTokenLimit = errors.New("too many API tokens")

// APIToken is a personal token for the account API.
type APIToken struct {
	ID         int64
	UserID     int64
	Name       string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time // zero = no expiry
}

// CreateAPIToken stores the hash of token. ttl 0 means no expiry.
func (s *Store) CreateAPIToken(ctx context.Context, userID int64, name, token string, ttl time.Duration) (*APIToken, error) {
	t := time.Now().Unix()
	var exp int64
	if ttl > 0 {
		exp = time.Now().Add(ttl).Unix()
	}
	var id int64
	err := s.write(ctx, func(tx *sql.Tx) error {
		var disabled bool
		if err := tx.QueryRowContext(ctx, `SELECT disabled FROM users WHERE id=?`, userID).Scan(&disabled); err != nil {
			return err
		}
		if disabled {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM api_tokens WHERE user_id = ? AND expires_at > 0 AND expires_at <= ?`, userID, t); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_tokens WHERE user_id = ?`, userID).Scan(&count); err != nil {
			return err
		}
		if count >= MaxAPITokens {
			return ErrTokenLimit
		}
		return tx.QueryRowContext(ctx, `INSERT INTO api_tokens (user_id, hash, name, created_at, expires_at)
			SELECT id, ?, ?, ?, ? FROM users WHERE id=? AND disabled=0 RETURNING id`, hashToken(token), name, t, exp, userID).Scan(&id)
	})
	if err != nil {
		return nil, err
	}
	at := &APIToken{ID: id, UserID: userID, Name: name, CreatedAt: time.Unix(t, 0)}
	if exp != 0 {
		at.ExpiresAt = time.Unix(exp, 0)
	}
	return at, nil
}

// LookupAPIToken returns the owner of a valid token and records its use.
func (s *Store) LookupAPIToken(ctx context.Context, token string) (*APIToken, *User, error) {
	var at APIToken
	var created, used, exp int64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, name, created_at, last_used_at, expires_at
		FROM api_tokens WHERE hash = ?`, hashToken(token)).Scan(&at.ID, &at.UserID, &at.Name, &created, &used, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().Unix()
	if exp != 0 && now >= exp {
		return nil, nil, ErrNotFound
	}
	at.CreatedAt, at.LastUsedAt = time.Unix(created, 0), time.Unix(used, 0)
	if exp != 0 {
		at.ExpiresAt = time.Unix(exp, 0)
	}
	u, err := s.UserByID(ctx, at.UserID)
	if err != nil || u.Disabled {
		if err == nil {
			err = ErrNotFound
		}
		return nil, nil, err
	}
	if now-used >= 60 {
		_ = s.write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, now, at.ID)
			return err
		})
	}
	return &at, u, nil
}

// ListAPITokens returns a user's tokens, newest first.
func (s *Store) ListAPITokens(ctx context.Context, userID int64) ([]*APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, created_at, last_used_at, expires_at
		FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC, id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIToken
	for rows.Next() {
		var at APIToken
		var c, u, e int64
		if err := rows.Scan(&at.ID, &at.UserID, &at.Name, &c, &u, &e); err != nil {
			return nil, err
		}
		at.CreatedAt, at.LastUsedAt = time.Unix(c, 0), time.Unix(u, 0)
		if e != 0 {
			at.ExpiresAt = time.Unix(e, 0)
		}
		out = append(out, &at)
	}
	return out, rows.Err()
}

// DeleteAPIToken revokes one of the user's tokens.
func (s *Store) DeleteAPIToken(ctx context.Context, userID, id int64) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ? AND user_id = ?`, id, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}
