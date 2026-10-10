package meta

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

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
		return tx.QueryRowContext(ctx, `INSERT INTO api_tokens (user_id, hash, name, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?) RETURNING id`, userID, hashToken(token), name, t, exp).Scan(&id)
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
	if exp != 0 && now > exp {
		return nil, nil, ErrNotFound
	}
	at.CreatedAt, at.LastUsedAt = time.Unix(created, 0), time.Unix(used, 0)
	if exp != 0 {
		at.ExpiresAt = time.Unix(exp, 0)
	}
	u, err := s.UserByID(ctx, at.UserID)
	if err != nil {
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
