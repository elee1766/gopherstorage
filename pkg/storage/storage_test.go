package storage_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/rsserver/rstest"

	"github.com/elee1766/gopherstorage/pkg/blob"
	"github.com/elee1766/gopherstorage/pkg/blob/filesystem"
	"github.com/elee1766/gopherstorage/pkg/blob/s3"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"github.com/elee1766/gopherstorage/pkg/storage"
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
	blobs, err := filesystem.New(t.TempDir())
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
	blobs, err := filesystem.New(t.TempDir())
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
	legacyBody := strings.NewReader("x")
	if _, err := svc.ForUser(u).Put(ctx, "/blocked", legacyBody, 1, "text/plain", rsserver.Condition{}); err != rs.ErrQuotaExceeded {
		t.Fatalf("upload with unknown-size legacy pending blob = %v, want quota/capacity error", err)
	}
	if legacyBody.Len() != 1 {
		t.Fatal("legacy pending capacity rejection consumed request body")
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
	if _, err := svc.ForUser(u).Put(ctx, "/after-gc", strings.NewReader("x"), 1, "text/plain", rsserver.Condition{}); err != nil {
		t.Fatalf("upload after legacy pending GC: %v", err)
	}
}

type blockedUploadReader struct {
	ctx     context.Context
	started chan struct{}
	once    sync.Once
}

func (r *blockedUploadReader) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

type releasedUploadReader struct {
	started chan struct{}
	release chan struct{}
	reader  *strings.Reader
	once    sync.Once
}

func (r *releasedUploadReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return r.reader.Read(p)
}

func TestUploadReservationsAreAtomicAcrossStoresAndReleaseOnCancel(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "meta.db")
	blobs, err := filesystem.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	defer blobs.Close()
	meta1, err := meta.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer meta1.Close()
	u, err := meta1.UpsertUser(ctx, meta.Login{Sub: "reserve-sub", Username: "reserve-user"})
	if err != nil {
		t.Fatal(err)
	}
	if err := meta1.SetQuota(ctx, u.ID, 4); err != nil {
		t.Fatal(err)
	}
	u.QuotaBytes = 4
	svc1 := &storage.Service{Meta: meta1, Blobs: blobs, MaxStagingBytes: 8}
	backend1 := svc1.ForUser(u)
	if _, err := backend1.Put(ctx, "/replace", strings.NewReader("four"), 4, "text/plain", rsserver.Condition{}); err != nil {
		t.Fatal(err)
	}
	meta2, err := meta.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer meta2.Close()
	svc2 := &storage.Service{Meta: meta2, Blobs: blobs, MaxStagingBytes: 8}
	backend2 := svc2.ForUser(u)

	putCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader := &blockedUploadReader{ctx: putCtx, started: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := backend1.Put(putCtx, "/replace", reader, -1, "text/plain", rsserver.Condition{})
		result <- err
	}()
	select {
	case <-reader.started:
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not start reading after reserving capacity")
	}
	if _, err := meta2.DeleteDocument(ctx, u.ID, "/replace", rsserver.Condition{}); err != nil {
		t.Fatalf("delete during reserved replacement: %v", err)
	}

	// A second Store connection models another process. It must not be able to
	// reuse the old document's quota credit or read a second body concurrently.
	secondSamePath := strings.NewReader("next")
	if _, err := backend2.Put(ctx, "/replace", secondSamePath, 4, "text/plain", rsserver.Condition{}); err != rs.ErrConflict {
		t.Fatalf("concurrent replacement error = %v, want conflict", err)
	}
	if secondSamePath.Len() != 4 {
		t.Fatal("rejected concurrent replacement consumed request body")
	}
	secondPath := strings.NewReader("x")
	if _, err := backend2.Put(ctx, "/other", secondPath, 1, "text/plain", rsserver.Condition{}); err != rs.ErrQuotaExceeded {
		t.Fatalf("aggregate in-flight quota error = %v, want quota exceeded", err)
	}
	if secondPath.Len() != 1 {
		t.Fatal("quota-rejected upload consumed request body")
	}
	otherUser, err := meta2.UpsertUser(ctx, meta.Login{Sub: "reserve-other-sub", Username: "reserve-other-user"})
	if err != nil {
		t.Fatal(err)
	}
	stagingBody := strings.NewReader("12345")
	if _, err := svc2.ForUser(otherUser).Put(ctx, "/other", stagingBody, 5, "text/plain", rsserver.Condition{}); !errors.Is(err, meta.ErrUploadCapacity) {
		t.Fatalf("aggregate staging limit error = %v, want upload capacity exceeded", err)
	}
	if stagingBody.Len() != 5 {
		t.Fatal("staging-rejected upload consumed request body")
	}

	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled upload error = %v, want context canceled", err)
	}
	// Failed-upload blob cleanup must release both the pending row and durable
	// reservation so another replacement can proceed immediately.
	if _, err := backend2.Put(ctx, "/replace", strings.NewReader("new!"), 4, "text/plain", rsserver.Condition{}); err != nil {
		t.Fatalf("replacement after cancelled upload: %v", err)
	}
}

func TestPerUserConcurrentUploadSlotLimit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	m, err := meta.Open(ctx, filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	blobs, err := filesystem.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	defer blobs.Close()
	u, err := m.UpsertUser(ctx, meta.Login{Sub: "slots-sub", Username: "slots-user"})
	if err != nil {
		t.Fatal(err)
	}
	svc := &storage.Service{Meta: m, Blobs: blobs, MaxConcurrentUploads: 1, MaxStagingBytes: 8}
	backend := svc.ForUser(u)
	putCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	reader := &blockedUploadReader{ctx: putCtx, started: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := backend.Put(putCtx, "/first", reader, -1, "text/plain", rsserver.Condition{})
		result <- err
	}()
	select {
	case <-reader.started:
	case <-time.After(5 * time.Second):
		t.Fatal("first upload did not reach its body reader")
	}
	second := strings.NewReader("x")
	if _, err := backend.Put(ctx, "/second", second, 1, "text/plain", rsserver.Condition{}); !errors.Is(err, meta.ErrUploadCapacity) {
		t.Fatalf("second in-flight upload error = %v, want upload capacity exceeded", err)
	}
	if second.Len() != 1 {
		t.Fatal("slot-rejected upload consumed request body")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("first upload after cancellation = %v, want context canceled", err)
	}
}

func TestDisabledAccountCannotPublishUploadAlreadyInFlight(t *testing.T) {
	ctx := context.Background()
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(t, blobs)
	u, err := svc.Meta.UpsertUser(ctx, meta.Login{Sub: "disabled-put-sub", Username: "disabled-put-user"})
	if err != nil {
		t.Fatal(err)
	}
	backend := svc.ForUser(u)
	reader := &releasedUploadReader{started: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader("value")}
	result := make(chan error, 1)
	go func() {
		_, err := backend.Put(ctx, "/doc", reader, -1, "text/plain", rsserver.Condition{})
		result <- err
	}()
	select {
	case <-reader.started:
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not start reading its request body")
	}
	if err := svc.Meta.SetUserDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	close(reader.release)
	var httpErr *rsserver.HTTPError
	if err := <-result; !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusForbidden {
		t.Fatalf("in-flight Put after account disable = %v, want HTTP 403", err)
	}
	if _, err := svc.Meta.GetNode(ctx, u.ID, "/doc"); err != meta.ErrNotFound {
		t.Fatalf("document after disabled publication = %v, want not found", err)
	}
}

func TestCrashReservationReleasedByPendingBlobGC(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "meta.db")
	blobs, err := filesystem.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	defer blobs.Close()
	m, err := meta.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.UpsertUser(ctx, meta.Login{Sub: "crash-sub", Username: "crash-user"})
	if err != nil {
		t.Fatal(err)
	}
	key := meta.NewBlobKey()
	if _, err := m.ReserveUpload(ctx, u.ID, "/interrupted", key, 4, 0, 1, 4, 10_000, false); err != nil {
		t.Fatal(err)
	}
	if err := blobs.Put(ctx, key, strings.NewReader("dead"), 4); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening the real database represents process recovery. GC claims and
	// deletes the abandoned blob, then ForgetBlob cascades its reservation.
	m, err = meta.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	svc := &storage.Service{Meta: m, Blobs: blobs, MaxStagingBytes: 4, MaxConcurrentUploads: 1}
	if n, err := svc.CollectGarbage(ctx, -time.Second); err != nil || n != 1 {
		t.Fatalf("collect crash residue = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := svc.ForUser(u).Put(ctx, "/recovered", strings.NewReader("live"), 4, "text/plain", rsserver.Condition{}); err != nil {
		t.Fatalf("upload after crash reservation GC: %v", err)
	}
}

func TestOrphanBlobCleanupDebtConsumesStagingCapacity(t *testing.T) {
	ctx := context.Background()
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(t, blobs)
	u, err := svc.Meta.UpsertUser(ctx, meta.Login{Sub: "orphan-sub", Username: "orphan-user"})
	if err != nil {
		t.Fatal(err)
	}
	backend := svc.ForUser(u)
	if _, err := backend.Put(ctx, "/old", strings.NewReader("four"), 4, "text/plain", rsserver.Condition{}); err != nil {
		t.Fatal(err)
	}
	// Delete metadata but skip filesystem cleanup, modeling a process exit after
	// the transaction that marks the former blob as an orphan.
	if _, err := svc.Meta.DeleteDocument(ctx, u.ID, "/old", rsserver.Condition{}); err != nil {
		t.Fatal(err)
	}
	svc.MaxStagingBytes = 3
	body := strings.NewReader("x")
	if _, err := backend.Put(ctx, "/new", body, 1, "text/plain", rsserver.Condition{}); !errors.Is(err, meta.ErrUploadCapacity) {
		t.Fatalf("upload while orphan exceeds staging cap = %v, want upload capacity exceeded", err)
	}
	if body.Len() != 1 {
		t.Fatal("capacity-rejected upload consumed request body")
	}
	if n, err := svc.CollectGarbage(ctx, 0); err != nil || n != 1 {
		t.Fatalf("collect orphan = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := backend.Put(ctx, "/new", strings.NewReader("x"), 1, "text/plain", rsserver.Condition{}); err != nil {
		t.Fatalf("upload after orphan cleanup: %v", err)
	}
}

func TestFolderListingLimitReturnsErrorInsteadOfPartialListing(t *testing.T) {
	ctx := context.Background()
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := newService(t, blobs)
	svc.MaxFolderChildren = 3
	if _, err := svc.Meta.UpsertUser(ctx, meta.Login{Sub: "listing-sub", Username: "listing-user"}); err != nil {
		t.Fatal(err)
	}
	u, err := svc.Meta.UserByName(ctx, "listing-user")
	if err != nil {
		t.Fatal(err)
	}
	backend := svc.ForUser(u)
	for _, p := range []string{"/folder/a", "/folder/b", "/folder/c"} {
		if _, err := backend.Put(ctx, p, strings.NewReader("x"), 1, "text/plain", rsserver.Condition{}); err != nil {
			t.Fatal(err)
		}
	}
	svc.MaxFolderChildren = 2
	if _, _, err := backend.Get(ctx, "/folder/"); err != rs.ErrTooLarge {
		t.Fatalf("over-limit folder listing error = %v, want too large", err)
	}
	newChild := strings.NewReader("x")
	if _, err := backend.Put(ctx, "/folder/d", newChild, 1, "text/plain", rsserver.Condition{}); err != rs.ErrTooLarge {
		t.Fatalf("new child over folder limit error = %v, want too large", err)
	}
	if newChild.Len() != 1 {
		t.Fatal("over-limit folder write consumed request body")
	}
	if _, err := backend.Put(ctx, "/folder/a", strings.NewReader("y"), 1, "text/plain", rsserver.Condition{}); err != nil {
		t.Fatalf("updating existing child in over-limit folder: %v", err)
	}
}

func TestConformanceFilesystem(t *testing.T) {
	b, err := filesystem.New(t.TempDir())
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
	b, err := s3.New(context.Background(), s3.Options{
		Endpoint: ep, Bucket: os.Getenv("GS_TEST_S3_BUCKET"),
		AccessKey: os.Getenv("GS_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("GS_TEST_S3_SECRET_KEY"),
		Prefix: "conformance-" + t.Name(), PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	runConformance(t, newService(t, b), 1<<20)
}
