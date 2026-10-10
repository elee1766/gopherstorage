package meta

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"
)

// Grant is an app a user has authorized.
type Grant struct {
	ID         int64
	UserID     int64
	ClientID   string
	ClientName string
	Scope      string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// UpsertGrant records that the user authorized client for scope.
func (s *Store) UpsertGrant(ctx context.Context, userID int64, clientID, clientName, scope string) (int64, error) {
	var id int64
	err := s.write(ctx, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			INSERT INTO grants (user_id, client_id, client_name, scope, created_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (user_id, client_id) DO UPDATE SET client_name = excluded.client_name, scope = excluded.scope
			RETURNING id`, userID, clientID, clientName, scope, now()).Scan(&id)
	})
	return id, err
}

// IssueToken stores a token for a grant. ttl 0 means no expiry.
func (s *Store) IssueToken(ctx context.Context, grantID int64, token, scope string, ttl time.Duration) error {
	var exp int64
	if ttl > 0 {
		exp = time.Now().Add(ttl).Unix()
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO tokens (hash, grant_id, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
			hashToken(token), grantID, scope, now(), exp)
		return err
	})
}

// TokenInfo is what a valid bearer token grants.
type TokenInfo struct {
	UserID   int64
	Username string
	GrantID  int64
	Scope    string
}

// LookupToken returns the grant of a valid, unexpired token.
func (s *Store) LookupToken(ctx context.Context, token string) (*TokenInfo, error) {
	var ti TokenInfo
	var exp int64
	err := s.db.QueryRowContext(ctx, `
		SELECT g.user_id, u.username, g.id, t.scope, t.expires_at
		FROM tokens t JOIN grants g ON g.id = t.grant_id JOIN users u ON u.id = g.user_id
		WHERE t.hash = ?`, hashToken(token)).Scan(&ti.UserID, &ti.Username, &ti.GrantID, &ti.Scope, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if exp != 0 && time.Now().Unix() > exp {
		return nil, ErrNotFound
	}
	return &ti, nil
}

// TouchGrant records use of a grant, at most once a minute.
func (s *Store) TouchGrant(ctx context.Context, grantID int64) error {
	t := now()
	return s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE grants SET last_used_at = ? WHERE id = ? AND last_used_at < ?`, t, grantID, t-60)
		return err
	})
}

// ListGrants returns the apps a user has authorized.
func (s *Store) ListGrants(ctx context.Context, userID int64) ([]*Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, client_id, client_name, scope, created_at, last_used_at
		FROM grants WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Grant
	for rows.Next() {
		var g Grant
		var c, l int64
		if err := rows.Scan(&g.ID, &g.UserID, &g.ClientID, &g.ClientName, &g.Scope, &c, &l); err != nil {
			return nil, err
		}
		g.CreatedAt, g.LastUsedAt = time.Unix(c, 0), time.Unix(l, 0)
		out = append(out, &g)
	}
	return out, rows.Err()
}

// RevokeGrant deletes a grant and all its tokens.
func (s *Store) RevokeGrant(ctx context.Context, userID, grantID int64) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM grants WHERE id = ? AND user_id = ?`, grantID, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// AuthCode is a pending PKCE authorization code.
type AuthCode struct {
	GrantID       int64
	RedirectURI   string
	Scope         string
	CodeChallenge string
}

// SaveAuthCode stores a one-time authorization code.
func (s *Store) SaveAuthCode(ctx context.Context, code string, c AuthCode, ttl time.Duration) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO auth_codes (hash, grant_id, redirect_uri, scope, code_challenge, expires_at)
			VALUES (?, ?, ?, ?, ?, ?)`, hashToken(code), c.GrantID, c.RedirectURI, c.Scope, c.CodeChallenge, time.Now().Add(ttl).Unix())
		return err
	})
}

// RedeemAuthCode deletes and returns a code. A code can only be redeemed once.
func (s *Store) RedeemAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	var c AuthCode
	err := s.write(ctx, func(tx *sql.Tx) error {
		var exp int64
		err := tx.QueryRowContext(ctx, `DELETE FROM auth_codes WHERE hash = ?
			RETURNING grant_id, redirect_uri, scope, code_challenge, expires_at`, hashToken(code)).
			Scan(&c.GrantID, &c.RedirectURI, &c.Scope, &c.CodeChallenge, &exp)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if time.Now().Unix() > exp {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// GrantUser returns the user id and client id of a grant.
func (s *Store) GrantUser(ctx context.Context, grantID int64) (userID int64, clientID string, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT user_id, client_id FROM grants WHERE id = ?`, grantID).Scan(&userID, &clientID)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return
}

// PruneExpired deletes expired tokens and codes.
func (s *Store) PruneExpired(ctx context.Context) error {
	t := now()
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM tokens WHERE expires_at > 0 AND expires_at < ?`, t); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM auth_codes WHERE expires_at < ?`, t)
		return err
	})
}
