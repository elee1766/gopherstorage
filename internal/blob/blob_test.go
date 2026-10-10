package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type failAfterOneReader struct {
	err  error
	sent bool
}

func (r *failAfterOneReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !r.sent {
		r.sent = true
		p[0] = 'x'
		return 1, nil
	}
	return 0, r.err
}

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

	ctx := context.Background()
	key := strings.Repeat("f", 32)
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	defer s.Delete(ctx, key)

	if err := s.Put(ctx, key, strings.NewReader(""), maxObjectSize+1); err != ErrTooLarge {
		t.Fatalf("oversized planned object error = %v, want ErrTooLarge", err)
	}

	readerErr := errors.New("injected reader failure")
	if err := s.Put(ctx, key, &failAfterOneReader{err: readerErr}, 1); !errors.Is(err, readerErr) {
		t.Fatalf("short S3 upload reader error = %v, want %v", err, readerErr)
	}

	objectKey := aws.ToString(s.key(key))
	siblingKey := objectKey + "/unrelated"
	stale, err := s.c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: s.bucket, Key: aws.String(objectKey)})
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := s.c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: s.bucket, Key: aws.String(siblingKey)})
	if err != nil {
		_, _ = s.c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: s.bucket, Key: aws.String(objectKey), UploadId: stale.UploadId})
		t.Fatal(err)
	}
	defer func() {
		_, _ = s.c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: s.bucket, Key: aws.String(objectKey), UploadId: stale.UploadId})
		_, _ = s.c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: s.bucket, Key: aws.String(siblingKey), UploadId: sibling.UploadId})
	}()
	if err := s.AbortIncomplete(ctx, key); err != nil {
		t.Fatal(err)
	}
	remaining, err := s.c.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: s.bucket, Prefix: aws.String(siblingKey)})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Uploads) != 1 || aws.ToString(remaining.Uploads[0].UploadId) != aws.ToString(sibling.UploadId) {
		t.Fatalf("sibling multipart upload was not preserved: %+v", remaining.Uploads)
	}

	r, err := s.Open(ctx, key, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err != ErrNotFound {
		t.Fatalf("object after failed S3 upload error = %v, want not found", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
