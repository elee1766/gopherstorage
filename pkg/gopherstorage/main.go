package gopherstorage

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/elee1766/gopherstorage/pkg/auth"
	"github.com/elee1766/gopherstorage/pkg/blob"
	"github.com/elee1766/gopherstorage/pkg/blob/filesystem"
	"github.com/elee1766/gopherstorage/pkg/blob/s3"
	"github.com/elee1766/gopherstorage/pkg/config"
	"github.com/elee1766/gopherstorage/pkg/importer"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"github.com/elee1766/gopherstorage/pkg/meta/sqlite"
	"github.com/elee1766/gopherstorage/pkg/oauth"
	"github.com/elee1766/gopherstorage/pkg/server"
	"github.com/elee1766/gopherstorage/pkg/storage"
)

// uploadGrace is how long an upload may run before its blob counts as abandoned.
const uploadGrace = 24 * time.Hour

// Run executes the daemon, configuration check, or offline import using args
// without a program name. The caller controls cancellation through ctx.
func Run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("gopherstorage", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "path to config file, empty uses environment only")
	check := fs.Bool("check", false, "validate the config and exit")
	importSource := fs.String("import", "", "import an existing directory into a user's storage while the server is stopped")
	importUser := fs.String("import-user", "", "existing storage username receiving the import")
	importPrefix := fs.String("import-prefix", "/", "destination folder, for example /archive/")
	importExisting := fs.String("import-existing", "skip", "existing document policy: skip, error, or replace")
	importWorkers := fs.Int("import-workers", 0, "parallel uploads, 0 selects up to 4 within the configured upload limit")
	importDryRun := fs.Bool("import-dry-run", false, "plan the import without writing documents or blobs")
	importVerbose := fs.Bool("import-verbose", false, "emit a JSON event for every source entry")
	importAllowPublic := fs.Bool("import-allow-public", false, "allow imported paths under /public/, where anyone can read them")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments; use -import for a source directory")
	}
	var importSet, importOptionsSet bool
	fs.Visit(func(f *flag.Flag) {
		importSet = importSet || f.Name == "import"
		importOptionsSet = importOptionsSet || strings.HasPrefix(f.Name, "import-")
	})
	if importSet && *importSource == "" {
		return errors.New("-import requires a source directory")
	}
	if importOptionsSet && *importSource == "" {
		return errors.New("-import-* options require -import")
	}
	if *importSource != "" && *check {
		return errors.New("-import cannot be combined with -check")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if *check {
		fmt.Println("config ok")
		return nil
	}

	if *importSource != "" {
		return runImport(ctx, cfg, importRequest{
			Source: *importSource, Username: *importUser, Prefix: *importPrefix,
			Existing: importer.Existing(*importExisting), Workers: *importWorkers,
			DryRun: *importDryRun, Verbose: *importVerbose, AllowPublic: *importAllowPublic,
		}, os.Stdout)
	}
	daemonCtx, cancelDaemon := context.WithCancel(ctx)
	defer cancelDaemon()
	initCtx, cancel := context.WithTimeout(daemonCtx, 30*time.Second)
	defer cancel()
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	if err := os.Chmod(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("protect data directory: %w", err)
	}
	unlock, err := acquireDataDirLock(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("lock data directory: %w", err)
	}
	defer unlock()

	store, err := sqlite.Open(initCtx, filepath.Join(cfg.DataDir, "meta.db"))
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

	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		maintenance(daemonCtx, svc, store)
	}()
	defer func() {
		cancelDaemon()
		<-maintenanceDone
	}()

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
	case <-daemonCtx.Done():
	}
	slog.Info("shutting down")
	sctx, scancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer scancel()
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func storageService(cfg *config.Config, store meta.Store, blobs blob.Store) *storage.Service {
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
func maintenance(ctx context.Context, svc *storage.Service, store meta.Store) {
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

func defaultConfigPath() string {
	if path, ok := os.LookupEnv("GOPHERSTORAGE_CONFIG"); ok {
		return path
	}
	if _, err := os.Lstat("config.yaml"); errors.Is(err, os.ErrNotExist) {
		return ""
	}
	return "config.yaml"
}
