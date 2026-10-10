package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3 stores blobs in an S3 compatible bucket.
type S3 struct {
	c      *s3.Client
	bucket *string
	prefix string
}

type S3Options struct {
	// Endpoint for non-AWS servers. Empty means AWS S3 in Region.
	Endpoint     string
	Region       string
	Bucket       string
	Prefix       string
	AccessKey    string
	SecretKey    string
	SessionToken string
	Insecure     bool
	PathStyle    bool
}

const (
	minPartSize = 16 << 20
	maxParts    = 10000
)

func NewS3(ctx context.Context, o S3Options) (*S3, error) {
	region := o.Region
	if region == "" {
		region = "us-east-1"
	}
	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if o.AccessKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(o.AccessKey, o.SecretKey, o.SessionToken)))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, err
	}
	endpoint := o.Endpoint
	if endpoint != "" && !strings.Contains(endpoint, "://") {
		if o.Insecure {
			endpoint = "http://" + endpoint
		} else {
			endpoint = "https://" + endpoint
		}
	}
	c := s3.NewFromConfig(cfg, func(so *s3.Options) {
		if endpoint != "" {
			so.BaseEndpoint = aws.String(strings.TrimRight(endpoint, "/"))
		}
		so.UsePathStyle = o.PathStyle
		// Default CRC32 trailers are rejected by many S3 compatible servers.
		so.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		so.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	s := &S3{c: c, bucket: aws.String(o.Bucket), prefix: strings.Trim(o.Prefix, "/")}
	if _, err := c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: s.bucket}); err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("bucket %q does not exist", o.Bucket)
		}
		return nil, fmt.Errorf("check bucket %q: %w", o.Bucket, err)
	}
	return s, nil
}

func isNotFound(err error) bool {
	var re *awshttp.ResponseError
	if errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotFound {
		return true
	}
	var nsk *types.NoSuchKey
	var nf *types.NotFound
	return errors.As(err, &nsk) || errors.As(err, &nf)
}

func (s *S3) key(k string) *string {
	if s.prefix == "" {
		return aws.String(shard(k))
	}
	return aws.String(s.prefix + "/" + shard(k))
}

// Put buffers one part at a time. Bodies under one part use a single
// PutObject; larger ones use a multipart upload.
func (s *S3) Put(ctx context.Context, k string, r io.Reader, size int64) error {
	if !validKey(k) {
		return errBadKey
	}
	key := s.key(k)
	partSize := int64(minPartSize)
	if size > 0 && (size+maxParts-1)/maxParts > partSize {
		partSize = (size + maxParts - 1) / maxParts
	}
	// Small known sizes only allocate what they need.
	first := partSize
	if size >= 0 && size < first {
		first = size
	}
	buf := make([]byte, first)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return err
	}
	if int64(n) < partSize {
		// Whole body fits in one part.
		var extra [1]byte
		if m, _ := io.ReadFull(r, extra[:]); m == 0 {
			_, err = s.c.PutObject(ctx, &s3.PutObjectInput{
				Bucket: s.bucket, Key: key, Body: bytes.NewReader(buf[:n]), ContentLength: aws.Int64(int64(n)),
			})
			return err
		}
		// More data than announced: continue as a multipart upload.
		buf = append(buf[:n], extra[0])
		buf = append(buf, make([]byte, partSize-int64(len(buf)))...)
		m, err := io.ReadFull(r, buf[n+1:])
		n += 1 + m
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return err
		}
	}

	mpu, err := s.c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: s.bucket, Key: key})
	if err != nil {
		return err
	}
	abort := func(cause error) error {
		_, aerr := s.c.AbortMultipartUpload(context.WithoutCancel(ctx), &s3.AbortMultipartUploadInput{
			Bucket: s.bucket, Key: key, UploadId: mpu.UploadId,
		})
		return errors.Join(cause, aerr)
	}
	var parts []types.CompletedPart
	for num := int32(1); ; num++ {
		if num > maxParts {
			return abort(errors.New("upload exceeds maximum number of parts"))
		}
		out, err := s.c.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: s.bucket, Key: key, UploadId: mpu.UploadId, PartNumber: aws.Int32(num),
			Body: bytes.NewReader(buf[:n]), ContentLength: aws.Int64(int64(n)),
		})
		if err != nil {
			return abort(err)
		}
		parts = append(parts, types.CompletedPart{ETag: out.ETag, PartNumber: aws.Int32(num)})
		n, err = io.ReadFull(r, buf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return abort(err)
		}
	}
	_, err = s.c.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: s.bucket, Key: key, UploadId: mpu.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		return abort(err)
	}
	return nil
}

func (s *S3) Open(ctx context.Context, k string, size int64) (io.ReadSeekCloser, error) {
	if !validKey(k) {
		return nil, errBadKey
	}
	return &s3Reader{ctx: ctx, s: s, key: s.key(k), size: size}, nil
}

func (s *S3) Delete(ctx context.Context, k string) error {
	if !validKey(k) {
		return errBadKey
	}
	_, err := s.c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: s.bucket, Key: s.key(k)})
	if err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

// s3Reader fetches the object lazily from the current offset, so seeking
// (used for range requests) does not download skipped bytes.
type s3Reader struct {
	ctx  context.Context
	s    *S3
	key  *string
	size int64
	off  int64
	body io.ReadCloser
}

func (r *s3Reader) Read(b []byte) (int, error) {
	if r.off >= r.size {
		return 0, io.EOF
	}
	if r.body == nil {
		out, err := r.s.c.GetObject(r.ctx, &s3.GetObjectInput{
			Bucket: r.s.bucket, Key: r.key, Range: aws.String(fmt.Sprintf("bytes=%d-", r.off)),
		})
		if err != nil {
			if isNotFound(err) {
				return 0, ErrNotFound
			}
			return 0, err
		}
		r.body = out.Body
	}
	n, err := r.body.Read(b)
	r.off += int64(n)
	if err == io.EOF && r.off < r.size {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (r *s3Reader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.off + offset
	case io.SeekEnd:
		abs = r.size + offset
	default:
		return 0, errors.New("invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("negative position")
	}
	if abs != r.off && r.body != nil {
		r.body.Close()
		r.body = nil
	}
	r.off = abs
	return abs, nil
}

func (r *s3Reader) Close() error {
	if r.body != nil {
		return r.body.Close()
	}
	return nil
}
