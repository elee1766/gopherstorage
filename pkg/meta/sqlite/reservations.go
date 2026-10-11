package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"anime.bike/remotestorage/pkg/rs"
	"github.com/elee1766/gopherstorage/pkg/meta"
)

// ReserveUpload atomically records an upload blob and its capacity reservation.
// A nonzero maxStagingBytes limits all in-flight reservations across the store.
// maxInFlight limits simultaneous reservations for one user.
func (s *Store) ReserveUpload(ctx context.Context, userID int64, path, blobKey string, reserveBytes, quota int64, maxInFlight int, maxStagingBytes int64, maxFolderChildren int, clamp bool) (int64, error) {
	if reserveBytes < 0 || maxInFlight <= 0 || maxStagingBytes <= 0 {
		return 0, meta.ErrUploadCapacity
	}
	reserved := reserveBytes
	err := s.write(ctx, func(tx *sql.Tx) error {
		var disabled bool
		if err := tx.QueryRowContext(ctx, `SELECT disabled FROM users WHERE id = ?`, userID).Scan(&disabled); err != nil {
			return err
		}
		if disabled {
			return meta.ErrAccountDisabled
		}
		old, err := getNode(ctx, tx, userID, path)
		if err != nil && !errors.Is(err, meta.ErrNotFound) {
			return err
		}
		var credit int64
		if old != nil && !old.IsFolder {
			credit = old.Size
		}
		if err := checkNewNodeChildren(ctx, tx, userID, path, old != nil && !old.IsFolder, maxFolderChildren); err != nil {
			return err
		}
		var pathReservation int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM upload_reservations WHERE user_id = ? AND path = ?`, userID, path).Scan(&pathReservation); err != nil {
			return err
		}
		if pathReservation != 0 {
			return rs.ErrConflict
		}

		var inFlight int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM upload_reservations WHERE user_id = ?`, userID).Scan(&inFlight); err != nil {
			return err
		}
		if inFlight >= maxInFlight {
			return meta.ErrUploadCapacity
		}
		var unknownPending bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(
			SELECT 1 FROM pending_blobs p WHERE p.size_bytes < 0
			AND NOT EXISTS (SELECT 1 FROM upload_reservations r WHERE r.blob_key = p.blob_key))`).Scan(&unknownPending); err != nil {
			return err
		}
		if unknownPending {
			return meta.ErrUploadCapacity
		}
		var staged int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(reserved_bytes + orphan_bytes), 0) +
			COALESCE((SELECT SUM(size_bytes) FROM pending_blobs WHERE reason IN ('orphan', 'collecting')), 0)
			FROM upload_reservations`).Scan(&staged); err != nil {
			return err
		}
		stagingAvailable := int64(0)
		if staged < maxStagingBytes {
			stagingAvailable = maxStagingBytes - staged
		}
		if credit > stagingAvailable {
			return meta.ErrUploadCapacity
		}
		stagingAvailable -= credit
		if reserved > stagingAvailable {
			if !clamp {
				return meta.ErrUploadCapacity
			}
			reserved = stagingAvailable
		}
		if quota > 0 {
			var used, committed int64
			if err := tx.QueryRowContext(ctx, `SELECT used_bytes FROM users WHERE id = ?`, userID).Scan(&used); err != nil {
				return err
			}
			if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(MAX(reserved_bytes - credit_bytes, 0)), 0) FROM upload_reservations WHERE user_id = ?`, userID).Scan(&committed); err != nil {
				return err
			}
			available := int64(0)
			if used < quota && committed < quota-used {
				available = quota - used - committed
			}
			quotaAllowance := int64(^uint64(0) >> 1)
			if credit <= quotaAllowance-available {
				quotaAllowance = available + credit
			}
			if reserved > quotaAllowance {
				if !clamp {
					return rs.ErrQuotaExceeded
				}
				reserved = quotaAllowance
			}
		}
		if err := addPending(ctx, tx, blobKey, "upload", 0); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO upload_reservations (blob_key, user_id, path, reserved_bytes, credit_bytes, orphan_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, blobKey, userID, path, reserved, credit, credit, now())
		if err != nil {
			// A concurrent upload of this same path already owns its replacement
			// credit. The writer transaction serializes this check across processes.
			return rs.ErrConflict
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return reserved, nil
}

// consumeUploadReservation requires the exact reservation to still exist and
// atomically releases it with publication of its node.
func consumeUploadReservation(ctx context.Context, tx *sql.Tx, userID int64, path, blobKey string, actualSize int64) error {
	res, err := tx.ExecContext(ctx, `DELETE FROM upload_reservations WHERE user_id = ? AND path = ? AND blob_key = ? AND reserved_bytes >= ?`, userID, path, blobKey, actualSize)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return rs.ErrConflict
	}
	return nil
}
