package meta

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineCollectionClaimsRecentAndFutureUploads(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for i := 0; i < 2; i++ {
		key := NewBlobKey()
		if err := store.AddPendingBlob(ctx, key); err != nil {
			t.Fatal(err)
		}
		// Clock skew must not strand an abandoned upload in an offline recovery.
		if i == 1 {
			if _, err := store.wdb.ExecContext(ctx, "UPDATE pending_blobs SET created_at = ? WHERE blob_key = ?", time.Now().Add(time.Hour).Unix(), key); err != nil {
				t.Fatal(err)
			}
		}
	}
	if rows, err := store.CollectableBlobs(ctx, 24*time.Hour, 100); err != nil || len(rows) != 0 {
		t.Fatalf("online collection claimed active uploads: %v %v", rows, err)
	}
	rows, err := store.CollectableBlobs(ctx, 0, 100)
	if err != nil || len(rows) != 2 {
		t.Fatalf("offline collection left abandoned uploads: %v %v", rows, err)
	}
	for _, row := range rows {
		if row.Reason != "collecting" {
			t.Fatalf("offline upload was not atomically claimed: %v", row)
		}
		if err := store.ForgetBlob(ctx, row.Key); err != nil {
			t.Fatal(err)
		}
	}
}
