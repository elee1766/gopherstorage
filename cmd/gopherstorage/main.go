package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/elee1766/gopherstorage/pkg/auth"
	"github.com/elee1766/gopherstorage/pkg/backup"
	"github.com/elee1766/gopherstorage/pkg/blob"
	"github.com/elee1766/gopherstorage/pkg/blob/filesystem"
	"github.com/elee1766/gopherstorage/pkg/blob/s3"
	"github.com/elee1766/gopherstorage/pkg/config"
	"github.com/elee1766/gopherstorage/pkg/importer"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"github.com/elee1766/gopherstorage/pkg/oauth"
	"github.com/elee1766/gopherstorage/pkg/server"
	"github.com/elee1766/gopherstorage/pkg/storage"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// uploadGrace is how long an upload may run before its blob counts as abandoned.
const uploadGrace = 24 * time.Hour

func run() error {
	cfgPath := flag.String("config", envOr("GOPHERSTORAGE_CONFIG", "config.yaml"), "path to config file")
	check := flag.Bool("check", false, "validate the config and exit")
	backupDest := flag.String("backup", "", "create an offline snapshot in a new destination directory")
	includeCredentials := flag.Bool("include-credentials", false, "retain credentials in a backup, allowing them to be restored")
	importSource := flag.String("import", "", "import an existing directory into a user's storage while the server is stopped")
	importUser := flag.String("import-user", "", "existing storage username receiving the import")
	importPrefix := flag.String("import-prefix", "/", "destination folder, for example /archive/")
	importExisting := flag.String("import-existing", "skip", "existing document policy: skip, error, or replace")
	importWorkers := flag.Int("import-workers", 0, "parallel uploads, 0 selects up to 4 within the configured upload limit")
	importDryRun := flag.Bool("import-dry-run", false, "plan the import without writing documents or blobs")
	importVerbose := flag.Bool("import-verbose", false, "emit a JSON event for every source entry")
	importAllowPublic := flag.Bool("import-allow-public", false, "allow imported paths under /public/, where anyone can read them")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments; use -import for a source directory")
	}
	var importSet, importOptionsSet bool
	flag.Visit(func(f *flag.Flag) {
		importSet = importSet || f.Name == "import"
		importOptionsSet = importOptionsSet || strings.HasPrefix(f.Name, "import-")
	})
	if importSet && *importSource == "" {
		return errors.New("-import requires a source directory")
	}
	if importOptionsSet && *importSource == "" {
		return errors.New("-import-* options require -import")
	}
	if *includeCredentials && *backupDest == "" {
		return errors.New("-include-credentials requires -backup")
	}
	if *check && *backupDest != "" {
		return errors.New("-check and -backup cannot be combined")
	}
	if *importSource != "" && (*check || *backupDest != "") {
		return errors.New("-import cannot be combined with -check or -backup")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if *check {
		fmt.Println("config ok")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *backupDest != "" {
		return runBackup(ctx, cfg, *backupDest, *includeCredentials)
	}
	if *importSource != "" {
		return runImport(ctx, cfg, importRequest{
			Source: *importSource, Username: *importUser, Prefix: *importPrefix,
			Existing: importer.Existing(*importExisting), Workers: *importWorkers,
			DryRun: *importDryRun, Verbose: *importVerbose, AllowPublic: *importAllowPublic,
		}, os.Stdout)
	}
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	if err := os.Chmod(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("protect data directory: %w", err)
	}
	unlock, err := backup.AcquireDataDirLock(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("lock data directory: %w", err)
	}
	defer unlock()

	store, err := meta.Open(initCtx, filepath.Join(cfg.DataDir, "meta.db"))
	if err != nil {
		return fmt.Errorf("open metadata: %w", err)
	}
	defer store.Close()

	blobs, err := openBlobs(initCtx, cfg)
	if err != nil {
		return fmt.Errorf("open blob storage: %w", err)
	}
	svc := storageService(cfg, store, blobs)

	a, err := auth.New(initCtx, cfg, store)
	if err != nil {
		return err
	}
	csrf := sha256.Sum256([]byte("gopherstorage/consent\x00" + cfg.Session.Secret))
	o := &oauth.Server{Auth: a, Store: store, TokenTTL: cfg.Tokens.TTL, AllowImplicit: cfg.Tokens.AllowImplicit, CSRFKey: csrf[:]}
	srv := server.New(cfg, store, svc, a, o)

	go maintenance(ctx, svc, store)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", cfg.Listen, "public_url", cfg.PublicURL, "storage", cfg.Storage.Backend)
		errc <- hs.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	slog.Info("shutting down")
	sctx, scancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer scancel()
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func storageService(cfg *config.Config, store *meta.Store, blobs blob.Store) *storage.Service {
	return &storage.Service{
		Meta: store, Blobs: blobs, DefaultQuota: cfg.Storage.DefaultQuotaBytes,
		MaxDocumentBytes:     cfg.Storage.MaxDocumentBytes,
		MaxConcurrentUploads: cfg.Storage.MaxConcurrentUploads,
		MaxStagingBytes:      cfg.Storage.MaxStagingBytes,
		MaxNodes:             cfg.Storage.MaxNodes,
		MaxFolderChildren:    cfg.Storage.MaxFolderChildren,
	}
}

func openBlobs(ctx context.Context, cfg *config.Config, opts ...blob.Option) (blob.Store, error) {
	switch cfg.Storage.Backend {
	case "s3":
		s := cfg.Storage.S3
		return s3.New(ctx, s3.Options{
			Endpoint: s.Endpoint, Region: s.Region, Bucket: s.Bucket, Prefix: s.Prefix,
			AccessKey: s.AccessKey, SecretKey: s.SecretKey, SessionToken: s.SessionToken,
			Insecure: s.Insecure, PathStyle: s.PathStyle,
		}, opts...)
	default:
		return filesystem.New(cfg.Storage.Path, opts...)
	}
}

// maintenance deletes orphaned blobs and expired tokens once an hour.
func maintenance(ctx context.Context, svc *storage.Service, store *meta.Store) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		cycleCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		if cleanup, ok := svc.Blobs.(interface {
			CleanupTemporary(context.Context, time.Duration) (int, error)
		}); ok {
			if n, err := cleanup.CleanupTemporary(cycleCtx, uploadGrace); err != nil {
				slog.Warn("temporary blob gc", "err", err)
			} else if n > 0 {
				slog.Info("temporary blob gc", "deleted", n)
			}
		}
		if n, err := svc.CollectGarbage(cycleCtx, uploadGrace); err != nil {
			slog.Warn("blob gc", "err", err)
		} else if n > 0 {
			slog.Info("blob gc", "deleted", n)
		}
		if err := store.PruneExpired(cycleCtx); err != nil {
			slog.Warn("token prune", "err", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
