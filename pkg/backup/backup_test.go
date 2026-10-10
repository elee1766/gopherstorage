package backup_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anime.bike/remotestorage/pkg/rsserver"
	"github.com/elee1766/gopherstorage/pkg/backup"
	"github.com/elee1766/gopherstorage/pkg/blob"
	"github.com/elee1766/gopherstorage/pkg/blob/filesystem"
	"github.com/elee1766/gopherstorage/pkg/config"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"github.com/elee1766/gopherstorage/pkg/storage"
)

func TestBackupRoundTripAndDataDirectoryExclusion(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	blobDir := filepath.Join(dataDir, "blobs")
	destination := filepath.Join(root, "snapshot")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sourceShard := func(key string) string { return "custom/" + key[:3] + "/" + key }
	blobs, err := filesystem.New(blobDir, blob.WithSharder(sourceShard))
	if err != nil {
		t.Fatal(err)
	}
	defer blobs.Close()
	store, err := meta.Open(ctx, filepath.Join(dataDir, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	user, err := store.UpsertUser(ctx, meta.Login{Sub: "backup-sub", Username: "backup-user"})
	if err != nil {
		t.Fatal(err)
	}
	apiToken, err := store.CreateAPIToken(ctx, user.ID, "backup-test", "api-secret", 0)
	if err != nil {
		t.Fatal(err)
	}
	grantID, err := store.UpsertGrant(ctx, user.ID, "https://app.example", "app", "notes:rw")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.IssueToken(ctx, grantID, "oauth-secret", "notes:rw", 0); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, "code-secret", meta.AuthCode{GrantID: grantID, RedirectURI: "https://app.example/cb", Scope: "notes:rw", CodeChallenge: "challenge"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	sessionHash := []byte("session-hash")
	if err := store.CreateSession(ctx, sessionHash, user.ID, "issuer", "subject", "sid", time.Hour); err != nil {
		t.Fatal(err)
	}
	credentialMarkers := [][]byte{sessionHash}
	for _, secret := range []string{"api-secret", "oauth-secret", "code-secret"} {
		hash := sha256.Sum256([]byte(secret))
		credentialMarkers = append(credentialMarkers, hash[:])
	}
	svc := &storage.Service{Meta: store, Blobs: blobs}
	if _, err := svc.ForUser(user).Put(ctx, "/notes/readme.txt", strings.NewReader("backup payload"), -1, "text/plain", rsserver.Condition{}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ForUser(user).Put(ctx, "/notes/readme.txt", strings.NewReader("backup payload"), -1, "text/plain", rsserver.Condition{}); err != nil {
		t.Fatalf("repeat identical document write: %v", err)
	}
	orphanKey := meta.NewBlobKey()
	if err := blobs.Put(ctx, orphanKey, strings.NewReader("not referenced"), -1); err != nil {
		t.Fatal(err)
	}

	release, err := backup.AcquireDataDirLock(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.AcquireDataDirLock(dataDir); !errors.Is(err, backup.ErrLocked) {
		t.Fatalf("second lock error = %v, want ErrLocked", err)
	}
	cfg := &config.Config{DataDir: dataDir, Storage: config.Storage{Backend: "filesystem", Path: blobDir}}
	if err := backup.Create(ctx, cfg, store, blobs, destination, false); err != nil {
		release()
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	unlock, err := backup.AcquireDataDirLock(dataDir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LookupAPIToken(ctx, "api-secret"); err != nil {
		t.Fatalf("backup changed live API token: %v", err)
	}
	if _, err := store.LookupToken(ctx, "oauth-secret"); err != nil {
		t.Fatalf("backup changed live OAuth token: %v", err)
	}
	if valid, err := store.ValidSession(ctx, sessionHash, user.ID); err != nil || !valid {
		t.Fatalf("backup changed live session: valid=%v err=%v", valid, err)
	}

	snapshot, err := meta.Open(ctx, filepath.Join(destination, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	scrubbedDBBytes, err := os.ReadFile(filepath.Join(destination, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	for i, marker := range credentialMarkers {
		if bytes.Contains(scrubbedDBBytes, marker) {
			t.Errorf("scrubbed snapshot contains credential marker %d", i)
		}
	}
	node, err := snapshot.GetNode(ctx, user.ID, "/notes/readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	snapshotBlobs, err := filesystem.New(filepath.Join(destination, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshotBlobs.Close()
	reader, err := snapshotBlobs.Open(ctx, node.BlobKey, node.Size)
	if err != nil {
		t.Fatal(err)
	}
	payload, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "backup payload" {
		t.Fatalf("snapshot document = %q", payload)
	}
	if tokens, err := snapshot.ListAPITokens(ctx, user.ID); err != nil || len(tokens) != 0 {
		t.Fatalf("snapshot API tokens = %d, error %v; want none", len(tokens), err)
	}
	if _, err := snapshot.LookupToken(ctx, "oauth-secret"); !errors.Is(err, meta.ErrNotFound) {
		t.Fatalf("snapshot OAuth token lookup error = %v, want not found", err)
	}
	if grants, err := snapshot.ListGrants(ctx, user.ID); err != nil || len(grants) != 0 {
		t.Fatalf("snapshot grants = %d, error %v; want none", len(grants), err)
	}
	if valid, err := snapshot.ValidSession(ctx, sessionHash, user.ID); err != nil || valid {
		t.Fatalf("snapshot session valid=%v error=%v; want revoked", valid, err)
	}
	if _, err := os.Stat(filepath.Join(destination, "blobs", orphanKey[:2], orphanKey[2:4], orphanKey)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unreferenced blob stat error = %v, want not-exist", err)
	}
	for path, mode := range map[string]os.FileMode{
		destination:                                 0o700,
		filepath.Join(destination, "meta.db"):       0o600,
		filepath.Join(destination, "manifest.json"): 0o600,
		filepath.Join(destination, "blobs", node.BlobKey[:2], node.BlobKey[2:4], node.BlobKey): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s mode = %04o, want %04o", path, info.Mode().Perm(), mode)
		}
	}

	secondRelease, err := backup.AcquireDataDirLock(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer secondRelease()
	withCredentials := filepath.Join(root, "snapshot-with-credentials")
	if err := backup.Create(ctx, cfg, store, blobs, withCredentials, true); err != nil {
		t.Fatal(err)
	}
	credentialSnapshot, err := meta.Open(ctx, filepath.Join(withCredentials, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer credentialSnapshot.Close()
	credentialDBBytes, err := os.ReadFile(filepath.Join(withCredentials, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	for i, marker := range credentialMarkers {
		if !bytes.Contains(credentialDBBytes, marker) {
			t.Errorf("credential-inclusive snapshot is missing credential marker %d", i)
		}
	}
	if tokens, err := credentialSnapshot.ListAPITokens(ctx, user.ID); err != nil || len(tokens) != 1 || tokens[0].ID != apiToken.ID {
		t.Fatalf("opt-in API credentials = %#v, error %v", tokens, err)
	}

	if err := os.WriteFile(filepath.Join(blobDir, filepath.FromSlash(sourceShard(node.BlobKey))), []byte("truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	failedDestination := filepath.Join(root, "invalid-snapshot")
	if err := backup.Create(ctx, cfg, store, blobs, failedDestination, false); err == nil {
		t.Fatal("backup with truncated referenced blob unexpectedly succeeded")
	}
	if _, err := os.Lstat(failedDestination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed backup destination stat error = %v, want not-exist", err)
	}
}
