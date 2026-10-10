package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/elee1766/gopherstorage/internal/backup"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/meta"
)

// runBackup is called by the -backup mode before any OIDC initialization.
func runBackup(ctx context.Context, cfg *config.Config, destination string, includeCredentials bool) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	release, err := backup.AcquireDataDirLock(cfg.DataDir)
	if err != nil {
		return err
	}
	defer release()
	if err := backup.ValidateDestination(cfg, destination); err != nil {
		return err
	}

	store, err := meta.Open(ctx, filepath.Join(cfg.DataDir, "meta.db"))
	if err != nil {
		return fmt.Errorf("open metadata: %w", err)
	}
	defer store.Close()
	blobs, err := openBlobs(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open blob storage: %w", err)
	}
	if closer, ok := blobs.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	if err := backup.Create(ctx, cfg, store, blobs, destination, includeCredentials); err != nil {
		return err
	}
	return nil
}
