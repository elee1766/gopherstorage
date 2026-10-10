//go:build linux

package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/elee1766/gopherstorage/pkg/blob"
	"github.com/elee1766/gopherstorage/pkg/config"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"golang.org/x/sys/unix"
)

type manifest struct {
	Format              int            `json:"format"`
	BlobBackend         string         `json:"blob_backend"`
	SourceBackend       string         `json:"source_backend"`
	CredentialsIncluded bool           `json:"credentials_included"`
	RequiredBlobs       []meta.BlobRef `json:"required_blobs"`
}

// Create writes a portable filesystem snapshot. The caller must hold the
// data-directory lock for the entire operation.
func Create(ctx context.Context, cfg *config.Config, store *meta.Store, blobs blob.Store, destination string, includeCredentials bool) (err error) {
	if cfg == nil || store == nil || blobs == nil {
		return errors.New("backup requires config, metadata store, and blob store")
	}
	if destination == "" {
		return errors.New("backup destination is empty")
	}
	if err := ValidateDestination(cfg, destination); err != nil {
		return err
	}
	dest, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent := filepath.Dir(dest)
	parent, err = filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("resolve backup parent: %w", err)
	}
	dest = filepath.Join(parent, filepath.Base(dest))

	stage, err := os.MkdirTemp(parent, ".gopherstorage-backup-*")
	if err != nil {
		return fmt.Errorf("create backup staging directory: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(stage))
		}
	}()
	if err = os.Chmod(stage, 0o700); err != nil {
		return err
	}

	metaPath := filepath.Join(stage, "meta.db")
	if err = store.Snapshot(ctx, metaPath, includeCredentials); err != nil {
		return err
	}
	if err = os.Chmod(metaPath, 0o600); err != nil {
		return err
	}
	if err = syncFile(metaPath); err != nil {
		return fmt.Errorf("sync metadata snapshot: %w", err)
	}
	refs, err := store.BlobRefs(ctx)
	if err != nil {
		return fmt.Errorf("list referenced blobs: %w", err)
	}
	for _, ref := range refs {
		if !validKey(ref.Key) {
			return fmt.Errorf("metadata contains invalid blob key %q", ref.Key)
		}
		if ref.Size < 0 || ref.Size == math.MaxInt64 {
			return fmt.Errorf("metadata contains invalid size for blob %s", ref.Key)
		}
		r, openErr := blobs.Open(ctx, ref.Key, ref.Size)
		if openErr != nil {
			return fmt.Errorf("open referenced blob %s: %w", ref.Key, openErr)
		}
		blobPath := filepath.Join(stage, "blobs", filepath.FromSlash(blob.DefaultShard(ref.Key)))
		if mkErr := os.MkdirAll(filepath.Dir(blobPath), 0o700); mkErr != nil {
			r.Close()
			return fmt.Errorf("create blob directory: %w", mkErr)
		}
		out, createErr := os.OpenFile(blobPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			r.Close()
			return fmt.Errorf("create backup blob %s: %w", ref.Key, createErr)
		}
		copied, copyErr := io.Copy(out, io.LimitReader(r, ref.Size+1))
		closeReadErr := r.Close()
		if copyErr == nil {
			copyErr = out.Sync()
		}
		closeWriteErr := out.Close()
		if err = errors.Join(copyErr, closeReadErr, closeWriteErr); err != nil {
			return fmt.Errorf("copy referenced blob %s: %w", ref.Key, err)
		}
		if copied != ref.Size {
			return fmt.Errorf("referenced blob %s size is %d, metadata records %d", ref.Key, copied, ref.Size)
		}
	}

	m := manifest{Format: 1, BlobBackend: "filesystem", SourceBackend: cfg.Storage.Backend, CredentialsIncluded: includeCredentials, RequiredBlobs: refs}
	manifestPath := filepath.Join(stage, "manifest.json")
	f, err := os.OpenFile(manifestPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encErr := json.NewEncoder(f).Encode(m)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err = errors.Join(encErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("write backup manifest: %w", err)
	}
	if err = syncDirectories(stage); err != nil {
		return fmt.Errorf("sync backup staging directories: %w", err)
	}
	if err = unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, dest, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish backup: %w", err)
	}
	if err = syncDirectory(parent); err != nil {
		return fmt.Errorf("backup published but parent sync failed: %w", err)
	}
	return nil
}

func syncDirectories(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := syncDirectory(dirs[i]); err != nil {
			return err
		}
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func validKey(key string) bool {
	if len(key) < 4 || len(key) > 128 {
		return false
	}
	for _, c := range key {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
