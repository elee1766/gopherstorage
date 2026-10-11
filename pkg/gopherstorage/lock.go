package gopherstorage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/gofrs/flock"
)

var errDataDirLocked = errors.New("data directory is already in use")

func acquireDataDirLock(dataDir string) (func() error, error) {
	if dataDir == "" {
		return nil, errors.New("data directory is empty")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	path := filepath.Join(dataDir, ".gopherstorage.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open data directory lock: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("protect data directory lock: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close data directory lock: %w", err)
	}

	lock := flock.New(path, flock.SetPermissions(0o600))
	locked, err := lock.TryLock()
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock data directory: %w", err)
	}
	if !locked {
		_ = lock.Close()
		return nil, errDataDirLocked
	}
	var once sync.Once
	var releaseErr error
	return func() error {
		once.Do(func() { releaseErr = lock.Close() })
		return releaseErr
	}, nil
}
