package gopherstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/elee1766/gopherstorage/pkg/auth"
	"github.com/elee1766/gopherstorage/pkg/blob"
	"github.com/elee1766/gopherstorage/pkg/config"
	"github.com/elee1766/gopherstorage/pkg/importer"
	"github.com/elee1766/gopherstorage/pkg/meta"
)

type importRequest struct {
	Source, Username, Prefix     string
	Existing                     importer.Existing
	Workers                      int
	DryRun, Verbose, AllowPublic bool
}

// runImport holds the offline lock and uses the same storage limits as the daemon.
func runImport(ctx context.Context, cfg *config.Config, req importRequest, output io.Writer) error {
	if !auth.ValidUsername(req.Username) {
		return errors.New("-import-user requires an existing storage username")
	}
	slots := cfg.Storage.MaxConcurrentUploads
	if slots == 0 {
		slots = 8
	}
	workers := req.Workers
	if workers == 0 {
		workers = min(4, slots)
	}
	if workers < 1 || workers > slots || workers > 64 {
		return fmt.Errorf("-import-workers must be between 1 and %d", min(slots, 64))
	}
	opts := importer.Options{Prefix: req.Prefix, Existing: req.Existing, Workers: workers,
		DryRun: req.DryRun, AllowPublic: req.AllowPublic, MaxDocumentBytes: cfg.Storage.MaxDocumentBytes}
	if err := opts.Validate(); err != nil {
		return err
	}
	source, sourceInfo, err := validateImportSource(cfg, req.Source)
	if err != nil {
		return err
	}
	pinned, err := importer.OpenSource(source)
	if err != nil {
		return err
	}
	defer pinned.Close()
	pinnedInfo, err := pinned.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(sourceInfo, pinnedInfo) {
		return errors.New("import source directory changed during preflight")
	}
	dbPath := filepath.Join(cfg.DataDir, "meta.db")
	st, err := os.Lstat(dbPath)
	if err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("import requires an existing regular metadata database at %q; start the server and have the user sign in first", dbPath)
	}
	release, err := acquireDataDirLock(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("import requires the server to be stopped: %w", err)
	}
	defer release()
	store, err := meta.OpenReadOnly(ctx, dbPath)
	if err != nil {
		return err
	}
	u, userErr := store.UserByName(ctx, req.Username)
	if userErr != nil || u.Disabled {
		store.Close()
		if errors.Is(userErr, meta.ErrNotFound) {
			return fmt.Errorf("user %q does not exist; have them sign in first", req.Username)
		}
		if userErr != nil {
			return userErr
		}
		return fmt.Errorf("user %q is disabled", req.Username)
	}
	if !req.DryRun {
		if err := store.Close(); err != nil {
			return err
		}
		store, err = meta.Open(ctx, dbPath)
		if err != nil {
			return err
		}
	}
	defer store.Close()
	var blobs blob.Store
	if !req.DryRun {
		initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		blobs, err = openBlobs(initCtx, cfg)
		cancel()
		if err != nil {
			return fmt.Errorf("open blob storage: %w", err)
		}
		if closer, ok := blobs.(interface{ Close() error }); ok {
			defer closer.Close()
		}
	}
	svc := storageService(cfg, store, blobs)
	if !req.DryRun {
		// No uploads can be active while this process holds the offline lock.
		gcCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		_, err := svc.CollectGarbage(gcCtx, 0)
		cancel()
		if err != nil {
			return fmt.Errorf("recover abandoned uploads before import: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	started, lastReport := time.Now(), time.Now()
	enc := json.NewEncoder(output)
	var completed int64
	var reportErr error
	opts.Progress = func(e importer.Event) {
		completed++
		if reportErr != nil {
			return
		}
		if req.Verbose || e.Action == "failed" || e.Action == "unsupported" {
			var msg string
			if e.Err != nil {
				msg = e.Err.Error()
			}
			reportErr = enc.Encode(struct {
				Event string `json:"event"`
				Path  string `json:"path"`
				Bytes int64  `json:"bytes"`
				Error string `json:"error,omitempty"`
			}{e.Action, e.Path, e.Bytes, msg})
		} else if completed%1000 == 0 || time.Since(lastReport) >= 5*time.Second {
			reportErr = enc.Encode(struct {
				Event     string `json:"event"`
				Completed int64  `json:"completed"`
			}{"progress", completed})
			lastReport = time.Now()
		}
		if reportErr != nil {
			cancel()
		}
	}
	result, err := importer.RunSource(ctx, pinned, svc.ForUser(u), opts)
	summaryErr := enc.Encode(struct {
		Event          string  `json:"event"`
		User           string  `json:"user"`
		DryRun         bool    `json:"dry_run"`
		Imported       int64   `json:"imported"`
		Planned        int64   `json:"planned"`
		Skipped        int64   `json:"skipped"`
		Unsupported    int64   `json:"unsupported"`
		Failed         int64   `json:"failed"`
		Bytes          int64   `json:"bytes"`
		ElapsedSeconds float64 `json:"elapsed_seconds"`
	}{"summary", req.Username, req.DryRun, result.Imported, result.Planned, result.Skipped,
		result.Unsupported, result.Failed, result.Bytes, time.Since(started).Seconds()})
	return errors.Join(err, reportErr, summaryErr)
}

func validateImportSource(cfg *config.Config, source string) (string, os.FileInfo, error) {
	if source == "" {
		return "", nil, errors.New("import source directory is empty")
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return "", nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", nil, fmt.Errorf("resolve import source: %w", err)
	}
	st, err := os.Stat(resolved)
	if err != nil || !st.IsDir() {
		return "", nil, fmt.Errorf("import source %q must be a directory", source)
	}
	protected := []string{cfg.DataDir}
	if cfg.Storage.Backend == "filesystem" || cfg.Storage.Backend == "" {
		blobPath := cfg.Storage.Path
		if blobPath == "" {
			blobPath = filepath.Join(cfg.DataDir, "blobs")
		}
		protected = append(protected, blobPath)
	}
	for _, dir := range protected {
		p, err := resolveImportProtectedPath(dir)
		if err != nil {
			return "", nil, fmt.Errorf("resolve storage directory: %w", err)
		}
		if importPathWithin(resolved, p) || importPathWithin(p, resolved) {
			return "", nil, fmt.Errorf("import source must not overlap the storage directory %q", p)
		}
	}
	return resolved, st, nil
}

func importPathWithin(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Resolve symlinks even when a configured blob directory has not been created yet.
func resolveImportProtectedPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(abs)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", err
		}
		suffix = append(suffix, filepath.Base(abs))
		abs = parent
	}
}
