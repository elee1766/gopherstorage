// Package storage implements rsserver.StorageBackend on the metadata store
// and a blob store.
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"

	"github.com/elee1766/gopherstorage/internal/blob"
	"github.com/elee1766/gopherstorage/internal/meta"
)

// Service gives out per-user backends.
type Service struct {
	Meta  *meta.Store
	Blobs blob.Store
	// DefaultQuota applies to users without their own quota. 0 = unlimited.
	DefaultQuota int64
	// MaxDocumentBytes limits one document. 0 = unlimited.
	MaxDocumentBytes int64
	// MaxConcurrentUploads limits in-flight uploads per user. 0 uses the safe default.
	MaxConcurrentUploads int
	// MaxStagingBytes limits aggregate in-flight bytes. 0 uses the safe default.
	MaxStagingBytes int64
	// MaxNodes limits documents and folders per user. 0 uses the safe default.
	MaxNodes int64
	// MaxFolderChildren limits the size of a folder listing. 0 uses the safe default.
	MaxFolderChildren int
}

const (
	defaultConcurrentUploads = 8
	defaultStagingBytes      = 2 << 30
	defaultMaxNodes          = 100_000
	defaultFolderChildren    = 10_000
)

func (s *Service) uploadLimits() (int, int64, int64, int) {
	slots, staging, nodes, children := s.MaxConcurrentUploads, s.MaxStagingBytes, s.MaxNodes, s.MaxFolderChildren
	if slots <= 0 {
		slots = defaultConcurrentUploads
	}
	if staging <= 0 {
		staging = defaultStagingBytes
	}
	if nodes <= 0 {
		nodes = defaultMaxNodes
	}
	if children <= 0 {
		children = defaultFolderChildren
	}
	return slots, staging, nodes, children
}

// ForUser returns the backend of a user.
func (s *Service) ForUser(u *meta.User) rsserver.StorageBackend {
	quota := u.QuotaBytes
	if quota == 0 {
		quota = s.DefaultQuota
	}
	return &userStorage{svc: s, userID: u.ID, quota: quota}
}

type userStorage struct {
	svc    *Service
	userID int64
	quota  int64
}

func (u *userStorage) Head(ctx context.Context, p string) (*rs.Metadata, error) {
	n, err := u.svc.Meta.GetNode(ctx, u.userID, p)
	if errors.Is(err, meta.ErrNotFound) {
		if rs.IsFolderPath(p) {
			return &rs.Metadata{Path: p, Name: rs.BaseName(p), IsFolder: true}, nil
		}
		return nil, rs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	m := n.Metadata()
	return &m, nil
}

func (u *userStorage) Get(ctx context.Context, p string) (*rs.Document, *rs.FolderListing, error) {
	if rs.IsFolderPath(p) {
		_, _, _, maxChildren := u.svc.uploadLimits()
		folder, children, err := u.svc.Meta.ListFolderLimit(ctx, u.userID, p, maxChildren)
		if err != nil {
			return nil, nil, err
		}
		l := rs.NewFolderListing(rs.Metadata{Path: p, Name: rs.BaseName(p), IsFolder: true})
		if folder != nil {
			l.Metadata.ETag = folder.ETag
		}
		for _, c := range children {
			if c.IsFolder {
				l.Items[rs.BaseName(c.Path)] = rs.FolderEntry(c.ETag)
			} else {
				l.Items[rs.BaseName(c.Path)] = rs.DocumentItem(c.Metadata())
			}
		}
		return nil, l, nil
	}
	n, err := u.svc.Meta.GetNode(ctx, u.userID, p)
	if errors.Is(err, meta.ErrNotFound) || (err == nil && n.IsFolder) {
		return nil, nil, rs.ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	body, err := u.svc.Blobs.Open(ctx, n.BlobKey, n.Size)
	if err != nil {
		return nil, nil, err
	}
	return &rs.Document{Metadata: n.Metadata(), Body: body}, nil, nil
}

// countingHasher hashes and counts what passes through it.
type countingHasher struct {
	r        io.Reader
	h        hash.Hash
	n        int64
	max      int64
	limited  bool
	exceeded bool
	limitErr error
}

func (c *countingHasher) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.limited {
		remaining := c.max - c.n
		if remaining <= 0 {
			var extra [1]byte
			n, err := c.r.Read(extra[:])
			if n > 0 {
				c.exceeded = true
				if c.limitErr != nil {
					return 0, c.limitErr
				}
				return 0, rs.ErrTooLarge
			}
			return 0, err
		}
		if int64(len(p)) > remaining {
			p = p[:remaining]
		}
	}
	n, err := c.r.Read(p)
	c.h.Write(p[:n])
	c.n += int64(n)
	return n, err
}

func (u *userStorage) Put(ctx context.Context, p string, body io.Reader, size int64, contentType string, cond rsserver.Condition) (*rsserver.PutResult, error) {
	if len(p) > 4096 || strings.Count(p, "/") > 65 {
		return nil, rs.ErrTooLarge
	}
	if u.svc.MaxDocumentBytes > 0 && size >= 0 && size > u.svc.MaxDocumentBytes {
		return nil, rs.ErrTooLarge
	}
	// Fail fast before uploading. The real checks run again atomically in PutDocument.
	var oldSize int64
	if cur, err := u.svc.Meta.GetNode(ctx, u.userID, p); err == nil && !cur.IsFolder {
		oldSize = cur.Size
		if err := cond.Check(true, cur.ETag); err != nil {
			return nil, err
		}
	} else if errors.Is(err, meta.ErrNotFound) {
		if err := cond.Check(false, ""); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	slots, staging, maxNodes, maxChildren := u.svc.uploadLimits()
	reserveBytes := size
	clamp := size < 0
	limitErr := error(rs.ErrTooLarge)
	if clamp {
		reserveBytes = staging
		limitErr = meta.ErrUploadCapacity
		if u.svc.MaxDocumentBytes > 0 && reserveBytes >= u.svc.MaxDocumentBytes {
			reserveBytes = u.svc.MaxDocumentBytes
			limitErr = rs.ErrTooLarge
		}
		if u.quota > 0 {
			_, used, err := u.svc.Meta.Usage(ctx, u.userID)
			if err != nil {
				return nil, err
			}
			available := u.quota - used
			if available < 0 {
				available = 0
			}
			const maxInt64 = int64(^uint64(0) >> 1)
			quotaAllowance := available
			if oldSize > maxInt64-quotaAllowance {
				quotaAllowance = maxInt64
			} else {
				quotaAllowance += oldSize
			}
			if reserveBytes > quotaAllowance {
				reserveBytes = quotaAllowance
				limitErr = rs.ErrQuotaExceeded
			}
		}
	} else if u.svc.MaxDocumentBytes > 0 && reserveBytes > u.svc.MaxDocumentBytes {
		return nil, rs.ErrTooLarge
	}
	key := meta.NewBlobKey()
	reserved, err := u.svc.Meta.ReserveUpload(ctx, u.userID, p, key, reserveBytes, u.quota, slots, staging, maxChildren, clamp)
	if err != nil {
		if errors.Is(err, meta.ErrAccountDisabled) {
			return nil, rsserver.NewHTTPError(http.StatusForbidden, "Account is disabled")
		}
		return nil, err
	}
	if reserved < reserveBytes {
		limitErr = rs.ErrQuotaExceeded
	}
	ch := &countingHasher{r: body, h: sha256.New(), max: reserved, limited: true, limitErr: limitErr}
	if err := u.svc.Blobs.Put(ctx, key, ch, size); err != nil {
		u.dropBlob(key)
		if errors.Is(err, blob.ErrTooLarge) {
			return nil, rs.ErrTooLarge
		}
		return nil, err
	}
	// Some blob implementations can finish a short-object upload after their
	// one-byte overflow probe observes the reader error. Do not commit that blob.
	if ch.exceeded {
		u.dropBlob(key)
		return nil, limitErr
	}
	if size >= 0 && ch.n != size {
		u.dropBlob(key)
		return nil, errors.New("request body shorter than Content-Length")
	}
	sum := ch.h.Sum(nil)
	res, err := u.svc.Meta.PutDocument(ctx, meta.PutDocument{
		UserID: u.userID, Path: p, ContentType: contentType, Size: ch.n,
		BlobKey: key, ETag: hex.EncodeToString(sum[:16]), Cond: cond, Quota: u.quota, MaxNodes: maxNodes, MaxFolderChildren: maxChildren,
	})
	if err != nil {
		u.dropBlob(key)
		if errors.Is(err, meta.ErrAccountDisabled) {
			return nil, rsserver.NewHTTPError(http.StatusForbidden, "Account is disabled")
		}
		return nil, err
	}
	if res.OldBlobKey != "" {
		u.dropBlob(res.OldBlobKey)
	}
	return &rsserver.PutResult{ETag: res.ETag, Created: res.Created}, nil
}

func (u *userStorage) Delete(ctx context.Context, p string, cond rsserver.Condition) (string, error) {
	res, err := u.svc.Meta.DeleteDocument(ctx, u.userID, p, cond)
	if err != nil {
		return "", err
	}
	if res.BlobKey != "" {
		u.dropBlob(res.BlobKey)
	}
	return res.ETag, nil
}

// dropBlob deletes an unreferenced blob. Failures are left to the collector.
func (u *userStorage) dropBlob(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if cleanup, ok := u.svc.Blobs.(interface {
		AbortIncomplete(context.Context, string) error
	}); ok {
		if err := cleanup.AbortIncomplete(ctx, key); err != nil {
			slog.Warn("incomplete blob cleanup failed, will retry", "key", key, "err", err)
			return
		}
	}
	if err := u.svc.Blobs.Delete(ctx, key); err != nil {
		slog.Warn("blob delete failed, will retry", "key", key, "err", err)
		return
	}
	if err := u.svc.Meta.ForgetBlob(ctx, key); err != nil {
		slog.Warn("forget blob failed", "key", key, "err", err)
	}
}

// CollectGarbage deletes blobs left behind by failed or interrupted writes.
// uploadGrace must exceed the longest upload, or in-flight uploads are deleted.
func (s *Service) CollectGarbage(ctx context.Context, uploadGrace time.Duration) (int, error) {
	total := 0
	for {
		batch, err := s.Meta.CollectableBlobs(ctx, uploadGrace, 500)
		if err != nil || len(batch) == 0 {
			return total, err
		}
		for _, b := range batch {
			if cleanup, ok := s.Blobs.(interface {
				AbortIncomplete(context.Context, string) error
			}); ok {
				if err := cleanup.AbortIncomplete(ctx, b.Key); err != nil {
					return total, err
				}
			}
			if err := s.Blobs.Delete(ctx, b.Key); err != nil {
				return total, err
			}
			if err := s.Meta.ForgetBlob(ctx, b.Key); err != nil {
				return total, err
			}
			total++
		}
	}
}
