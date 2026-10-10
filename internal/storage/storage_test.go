package storage_test

import (
	"context"
	"os"
	"sync"
	"testing"

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
