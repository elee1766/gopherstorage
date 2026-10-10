package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/elee1766/gopherstorage/pkg/blob"
)

// Store stores blobs in an S3-compatible bucket.
type Store struct {
	c      *s3.Client
	bucket *string
	prefix string
	mapper *blob.KeyMapper
}

type Options struct {
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
	// A 64 MiB cap keeps a 10,000-part object within 625 GiB and bounds buffers.
	maxPartSize = 64 << 20
	maxParts    = 10000

	s3OperationTimeout = 5 * time.Minute
	s3StartupTimeout   = 30 * time.Second
	s3DialTimeout      = 10 * time.Second
	s3HeaderTimeout    = 15 * time.Second
)

const maxObjectSize = int64(maxPartSize) * maxParts

// New connects to the configured bucket and returns an S3 blob store.
func New(ctx context.Context, o Options, opts ...blob.Option) (*Store, error) {
	mapper := blob.NewKeyMapper(opts...)
	ctx, cancel := context.WithTimeout(ctx, s3StartupTimeout)
	defer cancel()
	region := o.Region
	if region == "" {
		region = "us-east-1"
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: s3DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   s3DialTimeout,
		ResponseHeaderTimeout: s3HeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
		awsconfig.WithHTTPClient(&http.Client{Transport: transport}),
		awsconfig.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) { o.MaxAttempts = 3 })
		}),
	}
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
	s := &Store{c: c, bucket: aws.String(o.Bucket), prefix: strings.Trim(o.Prefix, "/"), mapper: mapper}
	if _, err := c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: s.bucket}); err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("bucket %q does not exist", o.Bucket)
		}
		return nil, fmt.Errorf("check bucket %q: %w", o.Bucket, err)
	}
	if s.prefix != "" {
		if _, err := c.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: s.bucket, Prefix: aws.String(s.prefix + "/"), MaxUploads: aws.Int32(1),
		}); err != nil {
			return nil, fmt.Errorf("check multipart-list permission for S3 prefix %q: %w", s.prefix, err)
		}
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

func (s *Store) key(k string) (*string, error) {
	p, err := s.mapper.Path(k)
	if err != nil {
		return nil, err
	}
	if s.prefix == "" {
		return aws.String(p), nil
	}
	return aws.String(s.prefix + "/" + p), nil
}

// Put buffers one part at a time. Bodies under one part use a single
// PutObject; larger ones use a multipart upload.
func (s *Store) Put(ctx context.Context, k string, r io.Reader, size int64) error {
	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()
	if size > maxObjectSize {
		return blob.ErrTooLarge
	}
	key, err := s.key(k)
	if err != nil {
		return err
	}
	partSize := int64(minPartSize)
	if size > 0 {
		planned := (size-1)/maxParts + 1
		if planned > partSize {
			partSize = planned
		}
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
		m, err := io.ReadFull(r, extra[:])
		if m == 0 && err != nil && err != io.EOF {
			return err
		}
		if m == 0 {
			_, err = s.c.PutObject(ctx, &s3.PutObjectInput{
				Bucket: s.bucket, Key: key, Body: bytes.NewReader(buf[:n]), ContentLength: aws.Int64(int64(n)),
			})
			return err
		}
		// More data than announced: continue as a multipart upload.
		buf = append(buf[:n], extra[0])
		buf = append(buf, make([]byte, partSize-int64(len(buf)))...)
		m, err = io.ReadFull(r, buf[n+1:])
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
		abortCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, aerr := s.c.AbortMultipartUpload(abortCtx, &s3.AbortMultipartUploadInput{
			Bucket: s.bucket, Key: key, UploadId: mpu.UploadId,
		})
		return errors.Join(cause, aerr)
	}
	var parts []types.CompletedPart
	for num := int32(1); ; num++ {
		if num > maxParts {
			return abort(blob.ErrTooLarge)
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

func (s *Store) Open(ctx context.Context, k string, size int64) (io.ReadSeekCloser, error) {
	key, err := s.key(k)
	if err != nil {
		return nil, err
	}
	readCtx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	return &s3Reader{ctx: readCtx, cancel: cancel, s: s, key: key, size: size}, nil
}

func (s *Store) Delete(ctx context.Context, k string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key, err := s.key(k)
	if err != nil {
		return err
	}
	_, err = s.c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: s.bucket, Key: key})
	if err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

// AbortIncomplete aborts multipart uploads for this application's exact blob key.
// The caller must keep the corresponding pending-blob record until this succeeds.
func (s *Store) AbortIncomplete(ctx context.Context, k string) error {
	ctx, cancel := context.WithTimeout(ctx, s3OperationTimeout)
	defer cancel()
	keyPtr, err := s.key(k)
	if err != nil {
		return err
	}
	key := aws.ToString(keyPtr)
	var keyMarker, uploadMarker *string
	for pages := 0; ; pages++ {
		if pages >= 100 {
			return errors.New("too many multipart uploads for blob key")
		}
		out, err := s.c.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: s.bucket, Prefix: aws.String(key), KeyMarker: keyMarker, UploadIdMarker: uploadMarker,
		})
		if err != nil {
			return fmt.Errorf("list multipart uploads for blob: %w", err)
		}
		for _, upload := range out.Uploads {
			if aws.ToString(upload.Key) != key {
				continue
			}
			if upload.UploadId == nil {
				return errors.New("multipart upload listing entry has no upload ID")
			}
			if _, err := s.c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket: s.bucket, Key: upload.Key, UploadId: upload.UploadId,
			}); err != nil {
				return fmt.Errorf("abort multipart upload for blob: %w", err)
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			return nil
		}
		if out.NextKeyMarker == nil {
			return errors.New("multipart upload listing truncated without a next key marker")
		}
		keyMarker, uploadMarker = out.NextKeyMarker, out.NextUploadIdMarker
	}
}

// s3Reader fetches the object lazily from the current offset, so seeking
// (used for range requests) does not download skipped bytes.
type s3Reader struct {
	ctx    context.Context
	cancel context.CancelFunc
	s      *Store
	key    *string
	size   int64
	off    int64
	body   io.ReadCloser
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
				return 0, blob.ErrNotFound
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
	defer func() {
		if r.cancel != nil {
			r.cancel()
		}
	}()
	if r.body != nil {
		err := r.body.Close()
		r.body = nil
		return err
	}
	return nil
}
