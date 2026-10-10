package s3

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/elee1766/gopherstorage/pkg/blob"

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

func TestS3MultipartCleanup(t *testing.T) {
	ep := os.Getenv("GS_TEST_S3_ENDPOINT")
	if ep == "" {
		t.Skip("GS_TEST_S3_ENDPOINT not set")
	}
	s, err := New(context.Background(), Options{
		Endpoint: ep, Bucket: os.Getenv("GS_TEST_S3_BUCKET"),
		AccessKey: os.Getenv("GS_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("GS_TEST_S3_SECRET_KEY"),
		Prefix: "blobtest", PathStyle: true,
	}, blob.WithSharder(func(key string) string { return "custom/" + key[:3] + "/" + key }))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := strings.Repeat("f", 32)
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	defer s.Delete(ctx, key)

	if err := s.Put(ctx, key, strings.NewReader(""), maxObjectSize+1); err != blob.ErrTooLarge {
		t.Fatalf("oversized planned object error = %v, want ErrTooLarge", err)
	}

	readerErr := errors.New("injected reader failure")
	if err := s.Put(ctx, key, &failAfterOneReader{err: readerErr}, 1); !errors.Is(err, readerErr) {
		t.Fatalf("short S3 upload reader error = %v, want %v", err, readerErr)
	}

	keyPtr, err := s.key(key)
	if err != nil {
		t.Fatal(err)
	}
	objectKey := aws.ToString(keyPtr)
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
	if _, err := io.ReadAll(r); err != blob.ErrNotFound {
		t.Fatalf("object after failed S3 upload error = %v, want not found", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
