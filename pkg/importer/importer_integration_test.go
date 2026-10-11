//go:build linux

package importer_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"github.com/elee1766/gopherstorage/pkg/blob/filesystem"
	"github.com/elee1766/gopherstorage/pkg/importer"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"github.com/elee1766/gopherstorage/pkg/meta/sqlite"
	"github.com/elee1766/gopherstorage/pkg/storage"
	"golang.org/x/sys/unix"
)

func TestRunStreamsAndResumesWithRealStorage(t *testing.T) {
	ctx := context.Background()
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "note.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "empty.bin"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "import-test", Username: "import-test"})
	if err != nil {
		t.Fatal(err)
	}
	backend := (&storage.Service{Meta: store, Blobs: blobs}).ForUser(u)
	res, err := importer.Run(ctx, source, backend, importer.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 2 || res.Bytes != 5 {
		t.Fatalf("result = %+v", res)
	}
	doc, _, err := backend.Get(ctx, "/nested/note.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(doc.Body)
	doc.Body.Close()
	if err != nil || string(got) != "hello" {
		t.Fatalf("body = %q, error = %v", got, err)
	}
	m, err := backend.Head(ctx, "/nested/note.txt")
	if err != nil || m.ContentType != "text/plain; charset=utf-8" {
		t.Fatalf("metadata = %+v, error = %v", m, err)
	}
	res, err = importer.Run(ctx, source, backend, importer.Options{})
	if err != nil || res.Skipped != 2 || res.Bytes != 0 {
		t.Fatalf("resume = %+v, error = %v", res, err)
	}
	if _, err := importer.Run(ctx, source, backend, importer.Options{Existing: importer.ExistingError}); err == nil {
		t.Fatal("existing=error succeeded")
	}
	if _, err := importer.Run(ctx, source, backend, importer.Options{Prefix: "/public/"}); err == nil {
		t.Fatal("public prefix accepted without opt-in")
	}
	if err := (importer.Options{Prefix: "/public/", AllowPublic: true}).Validate(); err != nil {
		t.Fatalf("allowed public prefix rejected: %v", err)
	}
	if _, _, err := backend.Get(ctx, "/empty.bin"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "note.txt"), []byte("updated"), 0600); err != nil {
		t.Fatal(err)
	}
	res, err = importer.Run(ctx, source, backend, importer.Options{Existing: importer.ExistingReplace})
	if err != nil || res.Imported != 2 || res.Bytes != 7 {
		t.Fatalf("replace = %+v, error = %v", res, err)
	}
	doc, _, err = backend.Get(ctx, "/nested/note.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(doc.Body)
	doc.Body.Close()
	if err != nil || string(got) != "updated" {
		t.Fatalf("replacement body = %q, error = %v", got, err)
	}
	listingDoc, listing, err := backend.Get(ctx, "/nested/")
	if err != nil || listingDoc != nil || listing == nil || len(listing.Items) != 1 {
		t.Fatalf("nested listing = %#v, document = %#v, error = %v", listing, listingDoc, err)
	}
	usedDocs, usedBytes, err := store.Usage(ctx, u.ID)
	if err != nil || usedDocs != 2 || usedBytes != 7 {
		t.Fatalf("usage = (%d docs, %d bytes), error = %v", usedDocs, usedBytes, err)
	}
}

func TestRunDrainsWorkersWhenWalkingFindsInvalidName(t *testing.T) {
	ctx := context.Background()
	source := t.TempDir()
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("a-%03d", i)
		if err := os.WriteFile(filepath.Join(source, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "z\x7f"), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "walk-error", Username: "walk-error"})
	if err != nil {
		t.Fatal(err)
	}
	backend := (&storage.Service{Meta: store, Blobs: blobs}).ForUser(u)
	result, err := importer.Run(ctx, source, backend, importer.Options{Workers: 4})
	if err == nil || result.Failed == 0 {
		t.Fatalf("invalid source name result = %+v, error = %v", result, err)
	}
}

func TestOpenSourcePinsDirectoryAcrossRenameAndRunSourceRepeat(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	original := filepath.Join(parent, "source")
	moved := filepath.Join(parent, "moved")
	decoy := filepath.Join(parent, "decoy")
	for _, dir := range []string{original, decoy} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(original, "value.txt"), []byte("pinned"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(decoy, "value.txt"), []byte("decoy"), 0600); err != nil {
		t.Fatal(err)
	}
	src, err := importer.OpenSource(original)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	before, err := src.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, original); err != nil {
		t.Fatal(err)
	}
	pinned, err := src.Stat()
	if err != nil || !os.SameFile(before, pinned) {
		t.Fatalf("pinned source stat = %v, initial = %v, error = %v", pinned, before, err)
	}
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "pinned-source", Username: "pinned-source"})
	if err != nil {
		t.Fatal(err)
	}
	backend := (&storage.Service{Meta: store, Blobs: blobs}).ForUser(u)
	first, err := importer.RunSource(ctx, src, backend, importer.Options{})
	if err != nil || first.Imported != 1 {
		t.Fatalf("first pinned run = %+v, error = %v", first, err)
	}
	second, err := importer.RunSource(ctx, src, backend, importer.Options{})
	if err != nil || second.Skipped != 1 {
		t.Fatalf("second pinned run = %+v, error = %v", second, err)
	}
	doc, _, err := backend.Get(ctx, "/value.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(doc.Body)
	doc.Body.Close()
	if err != nil || string(body) != "pinned" {
		t.Fatalf("pinned document = %q, error = %v", body, err)
	}
}

func TestRunRejectsSameSizeEditWithRestoredMtime(t *testing.T) {
	ctx := context.Background()
	sourceDir := t.TempDir()
	filePath := filepath.Join(sourceDir, "large.bin")
	const size = 64 << 20
	if err := os.WriteFile(filePath, bytes.Repeat([]byte("a"), size), 0600); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(filePath)
	if err != nil {
		t.Fatal(err)
	}
	src, err := importer.OpenSource(sourceDir)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	blobDir := t.TempDir()
	blobs, err := filesystem.New(blobDir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "mutated-source", Username: "mutated-source"})
	if err != nil {
		t.Fatal(err)
	}
	backend := (&storage.Service{Meta: store, Blobs: blobs}).ForUser(u)
	type runResult struct {
		result importer.Result
		err    error
	}
	done := make(chan runResult, 1)
	go func() {
		result, runErr := importer.RunSource(ctx, src, backend, importer.Options{})
		done <- runResult{result: result, err: runErr}
	}()
	deadline := time.Now().Add(10 * time.Second)
	mutated := false
	var run runResult
	finished := false
	for !mutated && !finished && time.Now().Before(deadline) {
		select {
		case run = <-done:
			finished = true
		default:
			entries, readErr := os.ReadDir(filepath.Join(blobDir, "tmp"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, entry := range entries {
				info, statErr := entry.Info()
				if statErr != nil {
					t.Fatal(statErr)
				}
				if info.Size() > 0 {
					f, openErr := os.OpenFile(filePath, os.O_WRONLY, 0)
					if openErr != nil {
						t.Fatal(openErr)
					}
					_, writeErr := f.WriteAt([]byte("b"), size/2)
					closeErr := f.Close()
					if writeErr != nil {
						t.Fatal(writeErr)
					}
					if closeErr != nil {
						t.Fatal(closeErr)
					}
					if err := os.Chtimes(filePath, original.ModTime(), original.ModTime()); err != nil {
						t.Fatal(err)
					}
					mutated = true
					break
				}
			}
			if !mutated {
				time.Sleep(time.Millisecond)
			}
		}
	}
	if !mutated {
		if !finished {
			run = <-done
		}
		t.Fatalf("source stream finished before mutation: %+v", run)
	}
	if !finished {
		run = <-done
	}
	if run.err == nil || run.result.Failed != 1 {
		t.Fatalf("same-size changed source result = %+v, error = %v", run.result, run.err)
	}
	if _, err := backend.Head(ctx, "/large.bin"); err != rs.ErrNotFound {
		t.Fatalf("changed source was committed: %v", err)
	}
}

func TestQuotaAndDocumentLimitRejectBeforeCommit(t *testing.T) {
	ctx := context.Background()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "doc.bin"), []byte("four"), 0600); err != nil {
		t.Fatal(err)
	}
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "limit-test", Username: "limit-test"})
	if err != nil {
		t.Fatal(err)
	}
	service := &storage.Service{Meta: store, Blobs: blobs, DefaultQuota: 3}
	backend := service.ForUser(u)
	result, err := importer.Run(ctx, source, backend, importer.Options{})
	if err != rs.ErrQuotaExceeded || result.Failed != 1 {
		t.Fatalf("quota result = %+v, error = %v", result, err)
	}
	if _, err := backend.Head(ctx, "/doc.bin"); err != rs.ErrNotFound {
		t.Fatalf("quota failure committed document: %v", err)
	}
	service.DefaultQuota = 0
	result, err = importer.Run(ctx, source, backend, importer.Options{MaxDocumentBytes: 3})
	if err != rs.ErrTooLarge || result.Failed != 1 {
		t.Fatalf("document limit result = %+v, error = %v", result, err)
	}
	if _, err := backend.Head(ctx, "/doc.bin"); err != rs.ErrNotFound {
		t.Fatalf("document limit committed file: %v", err)
	}
}

func TestCancellationPreservesCompletedWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := t.TempDir()
	const files = 100
	for i := 0; i < files; i++ {
		name := fmt.Sprintf("doc-%03d", i)
		if err := os.WriteFile(filepath.Join(source, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(context.Background(), meta.Login{Sub: "cancel-test", Username: "cancel-test"})
	if err != nil {
		t.Fatal(err)
	}
	backend := (&storage.Service{Meta: store, Blobs: blobs}).ForUser(u)
	var firstImported string
	result, err := importer.Run(ctx, source, backend, importer.Options{Workers: 1, Progress: func(event importer.Event) {
		if event.Action == importer.ActionImported {
			if firstImported == "" {
				firstImported = event.Path
			}
			cancel()
		}
	}})
	if !errors.Is(err, context.Canceled) || result.Imported < 1 || result.Imported >= files {
		t.Fatalf("cancel result = %+v, error = %v", result, err)
	}
	usedDocs, _, err := store.Usage(context.Background(), u.ID)
	if err != nil || usedDocs != result.Imported {
		t.Fatalf("durable documents = %d, result = %+v, error = %v", usedDocs, result, err)
	}
	first, err := backend.Head(context.Background(), firstImported)
	if firstImported == "" || err != nil || first == nil || first.IsFolder {
		t.Fatalf("first completed write path %q = %+v, error = %v", firstImported, first, err)
	}
}

func TestPublicFileRequiresExplicitOptIn(t *testing.T) {
	ctx := context.Background()
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "public"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "public", "shared.txt"), []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "public-test", Username: "public-test"})
	if err != nil {
		t.Fatal(err)
	}
	backend := (&storage.Service{Meta: store, Blobs: blobs}).ForUser(u)
	result, err := importer.Run(ctx, source, backend, importer.Options{})
	if err == nil || result.Failed != 1 {
		t.Fatalf("public import without opt-in = %+v, error = %v", result, err)
	}
	if _, err := backend.Head(ctx, "/public/shared.txt"); err != rs.ErrNotFound {
		t.Fatalf("public guard committed file: %v", err)
	}
	result, err = importer.Run(ctx, source, backend, importer.Options{AllowPublic: true})
	if err != nil || result.Imported != 1 {
		t.Fatalf("public import with opt-in = %+v, error = %v", result, err)
	}
}

func TestDryRunDoesNotWriteAndRejectsPublicFile(t *testing.T) {
	ctx := context.Background()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "x"), []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(source, "x"), filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(source, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "dry-test", Username: "dry-test"})
	if err != nil {
		t.Fatal(err)
	}
	backend := (&storage.Service{Meta: store, Blobs: blobs}).ForUser(u)
	res, err := importer.Run(ctx, source, backend, importer.Options{DryRun: true})
	if err != nil || res.Planned != 1 || res.Unsupported != 2 || res.Bytes != 3 {
		t.Fatalf("dry run = %+v, error = %v", res, err)
	}
	if _, err := backend.Head(ctx, "/x"); err != rs.ErrNotFound {
		t.Fatalf("dry run mutated backend: %v", err)
	}
	res, err = importer.Run(ctx, source, backend, importer.Options{DryRun: true, Prefix: "/public/"})
	if err == nil || res.Planned != 0 {
		t.Fatalf("public dry run = %+v, error = %v", res, err)
	}
}
