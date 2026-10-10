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
	"syscall"
	"time"

	"github.com/elee1766/gopherstorage/internal/auth"
	"github.com/elee1766/gopherstorage/internal/blob"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/meta"
	"github.com/elee1766/gopherstorage/internal/oauth"
	"github.com/elee1766/gopherstorage/internal/server"
	"github.com/elee1766/gopherstorage/internal/storage"
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
	flag.Parse()

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
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	store, err := meta.Open(initCtx, filepath.Join(cfg.DataDir, "meta.db"))
	if err != nil {
		return fmt.Errorf("open metadata: %w", err)
	}
	defer store.Close()

	blobs, err := openBlobs(initCtx, cfg)
	if err != nil {
		return fmt.Errorf("open blob storage: %w", err)
	}
	svc := &storage.Service{Meta: store, Blobs: blobs, DefaultQuota: cfg.Storage.DefaultQuotaBytes}

	a, err := auth.New(initCtx, cfg, store)
	if err != nil {
		return err
	}
	csrf := sha256.Sum256([]byte("gopherstorage/consent\x00" + cfg.Session.Secret))
	o := &oauth.Server{Auth: a, Store: store, TokenTTL: cfg.Tokens.TTL, CSRFKey: csrf[:]}
	srv := server.New(cfg, store, svc, a, o)

	go maintenance(ctx, svc, store)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
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

func openBlobs(ctx context.Context, cfg *config.Config) (blob.Store, error) {
	switch cfg.Storage.Backend {
	case "s3":
		s := cfg.Storage.S3
		return blob.NewS3(ctx, blob.S3Options{
			Endpoint: s.Endpoint, Region: s.Region, Bucket: s.Bucket, Prefix: s.Prefix,
			AccessKey: s.AccessKey, SecretKey: s.SecretKey, SessionToken: s.SessionToken,
			Insecure: s.Insecure, PathStyle: s.PathStyle,
		})
	default:
		return blob.NewFilesystem(cfg.Storage.Path)
	}
}

// maintenance deletes orphaned blobs and expired tokens once an hour.
func maintenance(ctx context.Context, svc *storage.Service, store *meta.Store) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := svc.CollectGarbage(ctx, uploadGrace); err != nil {
			slog.Warn("blob gc", "err", err)
		} else if n > 0 {
			slog.Info("blob gc", "deleted", n)
		}
		if err := store.PruneExpired(ctx); err != nil {
			slog.Warn("token prune", "err", err)
		}
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
