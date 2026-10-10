package blob_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elee1766/gopherstorage/pkg/blob"
	"github.com/elee1766/gopherstorage/pkg/blob/filesystem"
	blobS3 "github.com/elee1766/gopherstorage/pkg/blob/s3"
)

// Exercises empty/small/large uploads, range reads, and idempotent deletes.
func testStore(t *testing.T, store blob.Store) {
	t.Helper()
	ctx := context.Background()
	big := make([]byte, 40<<20+17)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data []byte
		size int64
	}{
		{"empty", nil, 0},
		{"small", []byte("hello"), 5},
		{"small-unknown", []byte("hello"), -1},
		{"big-known", big, int64(len(big))},
		{"big-unknown", big, -1},
	}
	for i, tc := range cases {
		key := "abcd000" + string(rune('0'+i)) + "0000000000000000000000ff"
		if err := store.Put(ctx, key, struct{ io.Reader }{bytes.NewReader(tc.data)}, tc.size); err != nil {
			t.Fatalf("%s: put: %v", tc.name, err)
		}
		r, err := store.Open(ctx, key, int64(len(tc.data)))
		if err != nil {
			t.Fatalf("%s: open: %v", tc.name, err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, tc.data) {
			t.Fatalf("%s: read back %d bytes, err %v", tc.name, len(got), err)
		}
		if len(tc.data) > 10 {
			off := int64(len(tc.data)) - 10
			if _, err := r.Seek(off, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			tail, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(tail, tc.data[off:]) {
				t.Fatalf("%s: seek read mismatch: %v", tc.name, err)
			}
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := store.Delete(ctx, key); err != nil {
			t.Fatalf("%s: delete: %v", tc.name, err)
		}
		if err := store.Delete(ctx, key); err != nil {
			t.Fatalf("%s: second delete: %v", tc.name, err)
		}
	}
}

func TestFilesystemStore(t *testing.T) {
	const key = "abcdef0123456789abcdef0123456789"
	for _, tc := range []struct {
		name   string
		option blob.Option
		path   string
	}{
		{name: "default", path: "ab/cd/abcdef0123456789abcdef0123456789"},
		{name: "flat", option: blob.WithSharder(func(k string) string { return k }), path: key},
		{name: "custom", option: blob.WithSharder(func(k string) string { return "custom/" + k[:3] + "/" + k }), path: "custom/abc/" + key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, err := filesystem.New(dir, tc.option)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(tc.path))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected pre-existing object: %v", err)
			}
			testStore(t, store)
			if err := store.Put(context.Background(), key, strings.NewReader("reopen"), 6); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(tc.path))); err != nil {
				t.Fatalf("stored object at %q: %v", tc.path, err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = filesystem.New(dir, tc.option)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			r, err := store.Open(context.Background(), key, 6)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil || string(got) != "reopen" {
				t.Fatalf("reopened object = %q, %v", got, err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if err := store.Delete(context.Background(), key); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(tc.path))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("object remains after delete: %v", err)
			}
		})
	}
}

type readObserver struct{ read bool }

func (r *readObserver) Read([]byte) (int, error) {
	r.read = true
	return 0, io.EOF
}

func TestFilesystemRejectsInvalidShardBeforeReadingBody(t *testing.T) {
	const key = "abcdef0123456789"
	for _, output := range []string{"tmp/" + key, "TMP/" + key, "../" + key, "dir/not-the-key", "dir\\" + key, "dir/\x00" + key, "C:/" + key} {
		t.Run(output, func(t *testing.T) {
			store, err := filesystem.New(t.TempDir(), blob.WithSharder(func(string) string { return output }))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			reader := &readObserver{}
			err = store.Put(context.Background(), key, reader, -1)
			if !errors.Is(err, blob.ErrInvalidShardPath) {
				t.Fatalf("Put error = %v, want ErrInvalidShardPath", err)
			}
			if reader.read {
				t.Fatal("Put consumed body before rejecting invalid shard path")
			}
		})
	}
}

func TestS3Store(t *testing.T) {
	endpoint := os.Getenv("GS_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("GS_TEST_S3_ENDPOINT not set")
	}
	for _, tc := range []struct {
		name   string
		option blob.Option
	}{
		{name: "default"},
		{name: "custom", option: blob.WithSharder(func(k string) string { return "custom/" + k[:3] + "/" + k })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := blobS3.New(context.Background(), blobS3.Options{
				Endpoint: endpoint, Bucket: os.Getenv("GS_TEST_S3_BUCKET"),
				AccessKey: os.Getenv("GS_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("GS_TEST_S3_SECRET_KEY"),
				Prefix: "blobtest", PathStyle: true,
			}, tc.option)
			if err != nil {
				t.Fatal(err)
			}
			testStore(t, store)
		})
	}
}
