package meta

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadOnlyMetadataCannotCreateOrModifyAccounts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "metadata #1.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	u, err := store.UpsertUser(ctx, Login{Sub: "readonly", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	ro, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if found, err := ro.UserByName(ctx, "alice"); err != nil || found.ID != u.ID {
		t.Fatalf("read-only lookup: %v %v", found, err)
	}
	if err := ro.SetQuota(ctx, u.ID, 42); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("read-only quota write: %v", err)
	}
	if _, err := ro.UpsertUser(ctx, Login{Sub: "new", Username: "bob"}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("read-only account creation: %v", err)
	}
	if _, err := ro.db.ExecContext(ctx, `UPDATE users SET quota_bytes=42`); err == nil {
		t.Fatal("read-only connection accepted a SQL write")
	}
	if found, err := ro.UserByName(ctx, "alice"); err != nil || found.QuotaBytes != 0 {
		t.Fatalf("read-only write changed quota: %v %v", found, err)
	}
	missing := filepath.Join(t.TempDir(), "missing.db")
	if db, err := OpenReadOnly(ctx, missing); err == nil {
		db.Close()
		t.Fatal("read-only open created a missing database")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing database exists after read-only open: %v", err)
	}
}
