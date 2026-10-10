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
		folder, children, err := u.svc.Meta.ListFolder(ctx, u.userID, p)
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
	r io.Reader
	h hash.Hash
	n int64
}

func (c *countingHasher) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.h.Write(p[:n])
	c.n += int64(n)
	return n, err
}

func (u *userStorage) Put(ctx context.Context, p string, body io.Reader, size int64, contentType string, cond rsserver.Condition) (*rsserver.PutResult, error) {
	// Fail fast before uploading. The real checks run again atomically in PutDocument.
	if cur, err := u.svc.Meta.GetNode(ctx, u.userID, p); err == nil && !cur.IsFolder {
		if err := cond.Check(true, cur.ETag); err != nil {
			return nil, err
		}
	} else if errors.Is(err, meta.ErrNotFound) {
		if err := cond.Check(false, ""); err != nil {
			return nil, err
		}
	}
	if u.quota > 0 && size > u.quota {
		return nil, rs.ErrQuotaExceeded
	}

	key := meta.NewBlobKey()
	if err := u.svc.Meta.AddPendingBlob(ctx, key); err != nil {
		return nil, err
	}
	ch := &countingHasher{r: body, h: sha256.New()}
	if err := u.svc.Blobs.Put(ctx, key, ch, size); err != nil {
		u.dropBlob(key)
		return nil, err
	}
	if size >= 0 && ch.n != size {
		u.dropBlob(key)
		return nil, errors.New("request body shorter than Content-Length")
	}
	sum := ch.h.Sum(nil)
	res, err := u.svc.Meta.PutDocument(ctx, meta.PutDocument{
		UserID: u.userID, Path: p, ContentType: contentType, Size: ch.n,
		BlobKey: key, ETag: hex.EncodeToString(sum[:16]), Cond: cond, Quota: u.quota,
	})
	if err != nil {
		u.dropBlob(key)
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
