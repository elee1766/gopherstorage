package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/elee1766/gopherstorage/pkg/meta"
)

// CreateSession records a server-side session using only a hash of its random identifier.
func (s *Store) CreateSession(ctx context.Context, id []byte, userID int64, issuer, subject, oidcSID string, ttl time.Duration) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<=?`, now()); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=?`, userID).Scan(&count); err != nil {
			return err
		}
		if count >= meta.MaxSessionsPerUser {
			return meta.ErrSessionLimit
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO sessions (id_hash, user_id, issuer, oidc_sub, oidc_sid, created_at, expires_at)
			SELECT ?, id, ?, ?, ?, ?, ? FROM users WHERE id = ? AND disabled = 0`, id, issuer, subject, oidcSID, now(), time.Now().Add(ttl).Unix(), userID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return meta.ErrNotFound
		}
		return nil
	})
}

// ValidSession checks both the session record and current account access state.
func (s *Store) ValidSession(ctx context.Context, id []byte, userID int64) (bool, error) {
	var valid bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id
		WHERE s.id_hash=? AND s.user_id=? AND s.expires_at>? AND u.disabled=0)`, id, userID, now()).Scan(&valid)
	return valid, err
}

// RevokeSession deletes a session by the hash of its opaque identifier.
func (s *Store) RevokeSession(ctx context.Context, id []byte) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, id)
		return err
	})
}

// SetUserDisabled atomically changes access state. Disabling also revokes all
// browser sessions and all local OAuth, authorization-code, and API credentials.
func (s *Store) SetUserDisabled(ctx context.Context, userID int64, disabled bool) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET disabled=? WHERE id=?`, disabled, userID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return meta.ErrNotFound
		}
		if !disabled {
			return nil
		}
		return revokeUserCredentialsTx(ctx, tx, userID)
	})
}

// RevokeUserCredentials removes all local credentials without changing account access state.
func (s *Store) RevokeUserCredentials(ctx context.Context, userID int64) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=?)`, userID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return meta.ErrNotFound
		}
		return revokeUserCredentialsTx(ctx, tx, userID)
	})
}

func revokeUserCredentialsTx(ctx context.Context, tx *sql.Tx, userID int64) error {
	for _, q := range []string{
		`DELETE FROM sessions WHERE user_id=?`,
		`DELETE FROM auth_codes WHERE grant_id IN (SELECT id FROM grants WHERE user_id=?)`,
		`DELETE FROM tokens WHERE grant_id IN (SELECT id FROM grants WHERE user_id=?)`,
		`DELETE FROM grants WHERE user_id=?`,
		`DELETE FROM api_tokens WHERE user_id=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, userID); err != nil {
			return err
		}
	}
	return nil
}

// RevokeOIDCLogout atomically records a logout token and revokes matching
// sessions. Subject-only logout also revokes all local credentials for that user.
func (s *Store) RevokeOIDCLogout(ctx context.Context, issuer, jti, subject, sid string, replayUntil time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM logout_replays WHERE expires_at<=?`, now()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO logout_replays (issuer,jti,expires_at) VALUES (?,?,?)`, issuer, jti, replayUntil.Unix()); err != nil {
			return err
		}
		var userID int64
		if subject != "" {
			if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE sub=?`, subject).Scan(&userID); err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if sid != "" {
			if subject != "" {
				if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE issuer=? AND oidc_sid=? AND oidc_sub=?`, issuer, sid, subject); err != nil {
					return err
				}
			} else if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE issuer=? AND oidc_sid=?`, issuer, sid); err != nil {
				return err
			}
		} else if userID != 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
				return err
			}
		}
		if subject != "" && sid == "" && userID != 0 {
			if err := revokeUserCredentialsTx(ctx, tx, userID); err != nil {
				return err
			}
		}
		return nil
	})
}
