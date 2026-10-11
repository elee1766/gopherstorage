//go:build linux

package gopherstorage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elee1766/gopherstorage/pkg/config"
	"github.com/elee1766/gopherstorage/pkg/importer"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"github.com/elee1766/gopherstorage/pkg/meta/sqlite"
)

func TestOfflineImportPreflightDryRunAndRecovery(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	source, data, blobs := filepath.Join(base, "export"), filepath.Join(base, "data"), filepath.Join(base, "blobs")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DataDir: data, Storage: config.Storage{Backend: "filesystem", Path: blobs,
		DefaultQuotaBytes: 1024, MaxDocumentBytes: 1024, MaxConcurrentUploads: 1}}
	dbPath := filepath.Join(data, "meta.db")
	store, err := sqlite.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "alice", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.UpsertUser(ctx, meta.Login{Sub: "bob", Username: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetUserDisabled(ctx, bob.ID, true); err != nil {
		t.Fatal(err)
	}
	pending := meta.NewBlobKey()
	if err := store.AddPendingBlob(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	req := importRequest{Source: source, Username: "alice", Prefix: "/notes/", Existing: importer.ExistingSkip, DryRun: true}
	var output bytes.Buffer
	if err := runImport(ctx, cfg, req, &output); err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Event                      string
		Imported, Planned, Skipped int64
		DryRun                     bool `json:"dry_run"`
	}
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil || summary.Event != "summary" || summary.Planned != 1 || summary.Imported != 0 || !summary.DryRun {
		t.Fatalf("dry-run summary: %s, %v", output.String(), err)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("dry run changed the metadata database")
	}
	if st, err := os.Stat(dbPath); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("dry run changed metadata permissions: %v %v", st, err)
	}
	if _, err := os.Stat(blobs); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run initialized blob storage: %v", err)
	}
	lockPath := filepath.Join(data, ".gopherstorage.lock")
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	release, err := acquireDataDirLock(data)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(lockPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("existing lock permissions: %v %v", st, err)
	}
	if err := runImport(ctx, cfg, req, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "stopped") || !errors.Is(err, errDataDirLocked) {
		t.Errorf("import while daemon lock held: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
	reacquire, err := acquireDataDirLock(data)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := reacquire(); err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"missing", "bob"} {
		q := req
		q.Username = username
		if err := runImport(ctx, cfg, q, &bytes.Buffer{}); err == nil {
			t.Errorf("import into unavailable user %q succeeded", username)
		}
	}
	badWorkers := req
	badWorkers.Workers = 2
	if err := runImport(ctx, cfg, badWorkers, &bytes.Buffer{}); err == nil {
		t.Fatal("import ignored the per-user upload slot limit")
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		t.Fatal(err)
	}
	req.DryRun = false
	output.Reset()
	if err := runImport(ctx, cfg, req, &output); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil || summary.Imported != 1 {
		t.Fatalf("actual import summary: %s %v", output.String(), err)
	}
	ro, err := sqlite.OpenReadOnly(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if n, err := ro.GetNode(ctx, u.ID, "/notes/hello.txt"); err != nil || n.Size != 5 {
		t.Fatalf("offline CLI did not publish document: %v %v", n, err)
	}
	output.Reset()
	if err := runImport(ctx, cfg, req, &output); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil || summary.Skipped != 1 || summary.Imported != 0 {
		t.Fatalf("resume summary: %s %v", output.String(), err)
	}
}

func TestRunUsesLocalFlagSet(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	config := "public_url: http://127.0.0.1:8080\noidc:\n  issuer: http://127.0.0.1:9000\n  client_id: test\nsession:\n  secret: 0123456789abcdef0123456789abcdef\ndata_dir: " + filepath.Join(t.TempDir(), "data") + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-config", configPath, "-check"}
	for range 2 {
		if err := Run(context.Background(), args); err != nil {
			t.Fatalf("repeat Run -check: %v", err)
		}
	}
	if err := Run(context.Background(), []string{"-h"}); err != nil {
		t.Fatalf("Run -h: %v", err)
	}
	if err := Run(context.Background(), []string{"-unknown"}); err == nil {
		t.Fatal("Run accepted an unknown flag")
	}
}

func TestImportRejectsSourceStorageOverlap(t *testing.T) {
	base := t.TempDir()
	data, blobs, export := filepath.Join(base, "data"), filepath.Join(base, "blobs"), filepath.Join(base, "export")
	for _, dir := range []string{data, blobs, export} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(base, "data-alias")
	if err := os.Symlink(data, alias); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DataDir: data, Storage: config.Storage{Backend: "filesystem", Path: blobs}}
	for _, source := range []string{base, data, blobs, alias} {
		if _, _, err := validateImportSource(cfg, source); err == nil {
			t.Errorf("allowed source overlapping storage: %q", source)
		}
	}
	if _, _, err := validateImportSource(cfg, export); err != nil {
		t.Fatal(err)
	}
	// A missing blob directory nested under the export is still unsafe.
	cfg.Storage.Path = filepath.Join(export, "new", "blobs")
	if _, _, err := validateImportSource(cfg, export); err == nil {
		t.Fatal("allowed source containing a not-yet-created blob directory")
	}
}
