package storage_test

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/rsserver/rstest"

	"github.com/elee1766/gopherstorage/internal/blob"
	"github.com/elee1766/gopherstorage/internal/meta"
	"github.com/elee1766/gopherstorage/internal/storage"
)

func newService(t *testing.T, blobs blob.Store) *storage.Service {
	ctx := context.Background()
	m, err := meta.Open(ctx, t.TempDir()+"/meta.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return &storage.Service{Meta: m, Blobs: blobs}
}

func runConformance(t *testing.T, svc *storage.Service, maxDoc int64) {
	var mu sync.Mutex
	h := rstest.NewHarness(t, func(user string) (rsserver.StorageBackend, error) {
		mu.Lock()
		defer mu.Unlock()
		u, err := svc.Meta.UpsertUser(context.Background(), meta.Login{Sub: "sub-" + user, Username: user})
		if err != nil {
			return nil, err
		}
		return svc.ForUser(u), nil
	}, func(b *rsserver.Builder) { b.WithMaxDocumentSize(maxDoc) })
	tg := h.Target("alice")
	tg.MaxDocumentSize = maxDoc
	rstest.Run(t, tg)

	// Every blob is referenced or was deleted: nothing left to collect.
	n, err := svc.CollectGarbage(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d blobs leaked", n)
	}
}

func TestQuotaStopsStreamingAtAvailableBytes(t *testing.T) {
	ctx := context.Background()
	blobs, err := blob.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(t, blobs)
	svc.DefaultQuota = 4
	u, err := svc.Meta.UpsertUser(ctx, meta.Login{Sub: "quota-sub", Username: "quota-user"})
	if err != nil {
		t.Fatal(err)
	}
	backend := svc.ForUser(u)
	body := strings.NewReader("0123456789")
	_, err = backend.Put(ctx, "/large.bin", body, -1, "application/octet-stream", rsserver.Condition{})
	if err != rs.ErrQuotaExceeded {
		t.Fatalf("Put error = %v, want quota exceeded", err)
	}
	if got := 10 - body.Len(); got != 5 {
		t.Fatalf("body bytes consumed = %d, want 5 (quota plus one-byte overflow probe)", got)
	}
	if n, err := svc.CollectGarbage(ctx, 0); err != nil || n != 0 {
		t.Fatalf("collect abandoned upload: deleted %d blobs, error %v", n, err)
	}

	old := strings.NewReader("old")
	if _, err := backend.Put(ctx, "/replace.bin", old, 3, "application/octet-stream", rsserver.Condition{}); err != nil {
		t.Fatalf("create replacement target: %v", err)
	}
	replacement := strings.NewReader("1234")
	if _, err := backend.Put(ctx, "/replace.bin", replacement, -1, "application/octet-stream", rsserver.Condition{}); err != nil {
		t.Fatalf("replace within freed-byte allowance: %v", err)
	}
	if got := 4 - replacement.Len(); got != 4 {
		t.Fatalf("replacement bytes consumed = %d, want 4", got)
	}

	tooLarge := strings.NewReader("0123456789")
	_, err = backend.Put(ctx, "/replace.bin", tooLarge, -1, "application/octet-stream", rsserver.Condition{})
	if err != rs.ErrQuotaExceeded {
		t.Fatalf("oversized replacement error = %v, want quota exceeded", err)
	}
	if got := 10 - tooLarge.Len(); got != 5 {
		t.Fatalf("oversized replacement bytes consumed = %d, want 5", got)
	}
	doc, _, err := backend.Get(ctx, "/replace.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Body.Close()
	content, err := io.ReadAll(doc.Body)
	if err != nil || string(content) != "1234" {
		t.Fatalf("replacement after rejected upload = %q, error %v", content, err)
	}
}

func TestGCClaimPreventsPublishingAgedPendingBlob(t *testing.T) {
	ctx := context.Background()
	blobs, err := blob.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(t, blobs)
	u, err := svc.Meta.UpsertUser(ctx, meta.Login{Sub: "gc-sub", Username: "gc-user"})
	if err != nil {
		t.Fatal(err)
	}
	key := meta.NewBlobKey()
	if err := blobs.Put(ctx, key, strings.NewReader("x"), 1); err != nil {
		t.Fatal(err)
	}
	if err := svc.Meta.AddPendingBlob(ctx, key); err != nil {
		t.Fatal(err)
	}
	claimed, err := svc.Meta.CollectableBlobs(ctx, -time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 1 || claimed[0].Key != key {
		t.Fatalf("collectable blobs = %#v, want pending key %q", claimed, key)
	}
	_, err = svc.Meta.PutDocument(ctx, meta.PutDocument{
		UserID: u.ID, Path: "/x", Size: 1, BlobKey: key, ETag: "etag",
	})
	if err != rs.ErrConflict {
		t.Fatalf("publish claimed blob error = %v, want conflict", err)
	}
	if n, err := svc.CollectGarbage(ctx, 0); err != nil || n != 1 {
		t.Fatalf("collect claimed blob: deleted %d blobs, error %v", n, err)
	}
	if _, err := svc.Meta.GetNode(ctx, u.ID, "/x"); err != meta.ErrNotFound {
		t.Fatalf("node after rejected publish = %v, want not found", err)
	}
	if _, err := blobs.Open(ctx, key, 1); err != blob.ErrNotFound {
		t.Fatalf("blob after collection error = %v, want not found", err)
	}
}

func TestConformanceFilesystem(t *testing.T) {
	b, err := blob.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runConformance(t, newService(t, b), 1<<20)
}

// Set GS_TEST_S3_ENDPOINT, GS_TEST_S3_BUCKET, GS_TEST_S3_ACCESS_KEY and
// GS_TEST_S3_SECRET_KEY to run against an S3 compatible server.
func TestConformanceS3(t *testing.T) {
	ep := os.Getenv("GS_TEST_S3_ENDPOINT")
	if ep == "" {
		t.Skip("GS_TEST_S3_ENDPOINT not set")
	}
	b, err := blob.NewS3(context.Background(), blob.S3Options{
		Endpoint: ep, Bucket: os.Getenv("GS_TEST_S3_BUCKET"),
		AccessKey: os.Getenv("GS_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("GS_TEST_S3_SECRET_KEY"),
		Prefix: "conformance-" + t.Name(), PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	runConformance(t, newService(t, b), 1<<20)
}
