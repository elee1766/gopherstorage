package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"testing"
)

// Exercises single-part, multipart, unknown-size, and range reads.
func testStore(t *testing.T, s Store) {
	ctx := context.Background()
	big := make([]byte, 40<<20+17)
	rand.Read(big)
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
	for i, c := range cases {
		key := "abcd000" + string(rune('0'+i)) + "0000000000000000000000ff"
		if err := s.Put(ctx, key, struct{ io.Reader }{bytes.NewReader(c.data)}, c.size); err != nil {
			t.Fatalf("%s: put: %v", c.name, err)
		}
		r, err := s.Open(ctx, key, int64(len(c.data)))
		if err != nil {
			t.Fatalf("%s: open: %v", c.name, err)
		}
		got, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(got, c.data) {
			t.Fatalf("%s: read back %d bytes, err %v", c.name, len(got), err)
		}
		if len(c.data) > 10 {
			off := int64(len(c.data)) - 10
			if _, err := r.Seek(off, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			tail, _ := io.ReadAll(r)
			if !bytes.Equal(tail, c.data[off:]) {
				t.Fatalf("%s: seek read mismatch", c.name)
			}
		}
		r.Close()
		if err := s.Delete(ctx, key); err != nil {
			t.Fatalf("%s: delete: %v", c.name, err)
		}
		if err := s.Delete(ctx, key); err != nil {
			t.Fatalf("%s: second delete: %v", c.name, err)
		}
	}
}

func TestFilesystemStore(t *testing.T) {
	s, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
}

func TestS3Store(t *testing.T) {
	ep := os.Getenv("GS_TEST_S3_ENDPOINT")
	if ep == "" {
		t.Skip("GS_TEST_S3_ENDPOINT not set")
	}
	s, err := NewS3(context.Background(), S3Options{
		Endpoint: ep, Bucket: os.Getenv("GS_TEST_S3_BUCKET"),
		AccessKey: os.Getenv("GS_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("GS_TEST_S3_SECRET_KEY"),
		Prefix: "blobtest", PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	testStore(t, s)
}
