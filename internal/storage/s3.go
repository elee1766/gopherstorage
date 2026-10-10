package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3 stores files in an S3 compatible bucket. Directories are key prefixes.
// Empty directories are kept with a zero byte "dir/" marker object.
type S3 struct {
	c      *s3.Client
	bucket *string
}

type S3Options struct {
	// Endpoint for non-AWS servers. Empty means AWS S3 in Region.
	Endpoint     string
	Region       string
	Bucket       string
	AccessKey    string
	SecretKey    string
	SessionToken string
	Insecure     bool
	PathStyle    bool
}

const (
	minPartSize   = 16 << 20
	maxParts      = 10000
	maxSingleCopy = 5 << 30
	copyPartSize  = 512 << 20
	dirMarkerType = "application/x-directory"
)

func NewS3(ctx context.Context, o S3Options) (*S3, error) {
	region := o.Region
	if region == "" {
		region = "us-east-1"
	}
	var loadOpts []func(*awsconfig.LoadOptions) error
	loadOpts = append(loadOpts, awsconfig.WithRegion(region))
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
	s := &S3{c: c, bucket: aws.String(o.Bucket)}
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

func contentType(p string, ct *string) string {
	c := aws.ToString(ct)
	if c == "" || c == "application/octet-stream" || c == "binary/octet-stream" {
		if byExt := mime.TypeByExtension(path.Ext(p)); byExt != "" {
			return byExt
		}
	}
	return c
}

func dirEntry(p string) Entry {
	e := Entry{Name: path.Base(p), Path: p, IsDir: true}
	if p == "" {
		e.Name = ""
	}
	return e
}

func (s *S3) head(ctx context.Context, key string) (*s3.HeadObjectOutput, error) {
	return s.c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: s.bucket, Key: aws.String(key)})
}

func headEntry(p string, h *s3.HeadObjectOutput) Entry {
	return Entry{
		Name:        path.Base(p),
		Path:        p,
		Size:        aws.ToInt64(h.ContentLength),
		ModTime:     aws.ToTime(h.LastModified).UTC(),
		ETag:        strings.Trim(aws.ToString(h.ETag), `"`),
		ContentType: contentType(p, h.ContentType),
	}
}

// dirExists reports whether anything is stored under p/. It lists with a
// delimiter so servers with implicit directories (SeaweedFS) are handled.
func (s *S3) dirExists(ctx context.Context, p string) (bool, error) {
	out, err := s.c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: s.bucket, Prefix: aws.String(p + "/"), Delimiter: aws.String("/"), MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return false, err
	}
	return len(out.Contents) > 0 || len(out.CommonPrefixes) > 0, nil
}

func (s *S3) Stat(ctx context.Context, p string) (Entry, error) {
	if p == "" {
		return dirEntry(""), nil
	}
	h, err := s.head(ctx, p)
	if err == nil {
		return headEntry(p, h), nil
	}
	if !isNotFound(err) {
		return Entry{}, err
	}
	ok, err := s.dirExists(ctx, p)
	if err != nil {
		return Entry{}, err
	}
	if !ok {
		return Entry{}, ErrNotExist
	}
	return dirEntry(p), nil
}

// listLevel returns the files and subdirectory prefixes directly under prefix.
func (s *S3) listLevel(ctx context.Context, prefix string) ([]types.Object, []string, error) {
	var objs []types.Object
	var dirs []string
	pg := s3.NewListObjectsV2Paginator(s.c, &s3.ListObjectsV2Input{
		Bucket: s.bucket, Prefix: aws.String(prefix), Delimiter: aws.String("/"),
	})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, o := range page.Contents {
			k := aws.ToString(o.Key)
			if k == prefix {
				continue // marker for this directory
			}
			if strings.HasSuffix(k, "/") {
				// Some servers return markers as objects instead of common prefixes.
				dirs = append(dirs, k)
				continue
			}
			objs = append(objs, o)
		}
		for _, cp := range page.CommonPrefixes {
			dirs = append(dirs, aws.ToString(cp.Prefix))
		}
	}
	return objs, dirs, nil
}

func (s *S3) List(ctx context.Context, dir string) ([]Entry, error) {
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	objs, dirs, err := s.listLevel(ctx, prefix)
	if err != nil {
		return nil, err
	}
	if dir != "" && len(objs) == 0 && len(dirs) == 0 {
		e, err := s.Stat(ctx, dir)
		if err != nil {
			return nil, err
		}
		if !e.IsDir {
			return nil, ErrNotDir
		}
	}
	seen := map[string]bool{}
	out := make([]Entry, 0, len(objs)+len(dirs))
	for _, d := range dirs {
		name := strings.TrimSuffix(strings.TrimPrefix(d, prefix), "/")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, dirEntry(Join(dir, name)))
	}
	for _, o := range objs {
		p := aws.ToString(o.Key)
		out = append(out, Entry{
			Name:        path.Base(p),
			Path:        p,
			Size:        aws.ToInt64(o.Size),
			ModTime:     aws.ToTime(o.LastModified).UTC(),
			ETag:        strings.Trim(aws.ToString(o.ETag), `"`),
			ContentType: mime.TypeByExtension(path.Ext(p)),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *S3) Open(ctx context.Context, p string) (io.ReadSeekCloser, Entry, error) {
	if p == "" {
		return nil, Entry{}, ErrIsDir
	}
	h, err := s.head(ctx, p)
	if err != nil {
		if isNotFound(err) {
			if ok, _ := s.dirExists(ctx, p); ok {
				return nil, Entry{}, ErrIsDir
			}
			return nil, Entry{}, ErrNotExist
		}
		return nil, Entry{}, err
	}
	e := headEntry(p, h)
	return &s3Reader{ctx: ctx, s: s, key: p, size: e.Size, etag: aws.ToString(h.ETag)}, e, nil
}

// s3Reader fetches the object lazily from the current offset, so seeking
// (used for range requests) does not download skipped bytes.
type s3Reader struct {
	ctx  context.Context
	s    *S3
	key  string
	etag string
	size int64
	off  int64
	body io.ReadCloser
}

func (r *s3Reader) Read(b []byte) (int, error) {
	if r.off >= r.size {
		return 0, io.EOF
	}
	if r.body == nil {
		in := &s3.GetObjectInput{Bucket: r.s.bucket, Key: aws.String(r.key), Range: aws.String(fmt.Sprintf("bytes=%d-", r.off))}
		if r.etag != "" {
			in.IfMatch = aws.String(r.etag)
		}
		out, err := r.s.c.GetObject(r.ctx, in)
		if err != nil {
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

// checkParents fails if any ancestor of p is a regular file.
func (s *S3) checkParents(ctx context.Context, p string) error {
	for dir := path.Dir(p); dir != "." && dir != "/"; dir = path.Dir(dir) {
		_, err := s.head(ctx, dir)
		if err == nil {
			return ErrNotDir
		}
		if !isNotFound(err) {
			return err
		}
	}
	return nil
}

func (s *S3) Put(ctx context.Context, p string, r io.Reader, size int64, ct string) (Entry, error) {
	if p == "" {
		return Entry{}, ErrIsDir
	}
	if ok, err := s.dirExists(ctx, p); err != nil {
		return Entry{}, err
	} else if ok {
		return Entry{}, ErrIsDir
	}
	if err := s.checkParents(ctx, p); err != nil {
		return Entry{}, err
	}
	if ct == "" {
		ct = mime.TypeByExtension(path.Ext(p))
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	if err := s.upload(ctx, p, r, size, ct); err != nil {
		return Entry{}, err
	}
	return s.Stat(ctx, p)
}

// upload buffers one part at a time. Bodies under one part use a single
// PutObject; larger ones use a multipart upload.
func (s *S3) upload(ctx context.Context, key string, r io.Reader, size int64, ct string) error {
	partSize := int64(minPartSize)
	if size > 0 && (size+maxParts-1)/maxParts > partSize {
		partSize = (size + maxParts - 1) / maxParts
	}
	buf := make([]byte, partSize)
	n, err := io.ReadFull(r, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		_, err = s.c.PutObject(ctx, &s3.PutObjectInput{
			Bucket: s.bucket, Key: aws.String(key), Body: bytes.NewReader(buf[:n]),
			ContentLength: aws.Int64(int64(n)), ContentType: aws.String(ct),
		})
		return err
	}
	if err != nil {
		return err
	}

	mpu, err := s.c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: s.bucket, Key: aws.String(key), ContentType: aws.String(ct),
	})
	if err != nil {
		return err
	}
	abort := func(cause error) error {
		// Use a fresh context so the abort still runs if ctx was canceled.
		_, aerr := s.c.AbortMultipartUpload(context.WithoutCancel(ctx), &s3.AbortMultipartUploadInput{
			Bucket: s.bucket, Key: aws.String(key), UploadId: mpu.UploadId,
		})
		return errors.Join(cause, aerr)
	}
	var parts []types.CompletedPart
	for num := int32(1); ; num++ {
		if num > maxParts {
			return abort(errors.New("upload exceeds maximum number of parts"))
		}
		out, err := s.c.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: s.bucket, Key: aws.String(key), UploadId: mpu.UploadId, PartNumber: aws.Int32(num),
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
		Bucket: s.bucket, Key: aws.String(key), UploadId: mpu.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		return abort(err)
	}
	return nil
}

func (s *S3) putMarker(ctx context.Context, key string) error {
	_, err := s.c.PutObject(ctx, &s3.PutObjectInput{
		Bucket: s.bucket, Key: aws.String(key), Body: bytes.NewReader(nil),
		ContentLength: aws.Int64(0), ContentType: aws.String(dirMarkerType),
	})
	return err
}

func (s *S3) Mkdir(ctx context.Context, p string) error {
	if p == "" {
		return nil
	}
	_, err := s.head(ctx, p)
	if err == nil {
		return ErrExist
	}
	if !isNotFound(err) {
		return err
	}
	if err := s.checkParents(ctx, p); err != nil {
		return err
	}
	return s.putMarker(ctx, p+"/")
}

// keepParent writes a marker for the parent of p so it survives removal of its last child.
func (s *S3) keepParent(ctx context.Context, p string) error {
	dir := path.Dir(p)
	if dir == "." || dir == "/" {
		return nil
	}
	return s.putMarker(ctx, dir+"/")
}

type s3Key struct {
	key  string
	size int64
}

// walk returns every key under prefix (which ends in "/"), including a "dir/"
// key for each subdirectory, ordered so children come before their parents.
// It lists one level at a time because some servers (SeaweedFS) keep implicit
// directories that recursive listings omit.
func (s *S3) walk(ctx context.Context, prefix string) ([]s3Key, error) {
	objs, dirs, err := s.listLevel(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var out []s3Key
	for _, d := range dirs {
		sub, err := s.walk(ctx, d)
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	for _, o := range objs {
		out = append(out, s3Key{key: aws.ToString(o.Key), size: aws.ToInt64(o.Size)})
	}
	return append(out, s3Key{key: prefix}), nil
}

func (s *S3) removeKeys(ctx context.Context, keys []s3Key) error {
	var files, dirs []string
	for _, k := range keys {
		if strings.HasSuffix(k.key, "/") {
			dirs = append(dirs, k.key)
		} else {
			files = append(files, k.key)
		}
	}
	for len(files) > 0 {
		batch := files[:min(len(files), 1000)]
		files = files[len(batch):]
		ids := make([]types.ObjectIdentifier, len(batch))
		for i, k := range batch {
			ids[i] = types.ObjectIdentifier{Key: aws.String(k)}
		}
		out, err := s.c.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: s.bucket, Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)},
		})
		if err != nil {
			return err
		}
		var errs []error
		for _, e := range out.Errors {
			errs = append(errs, fmt.Errorf("remove %s: %s", aws.ToString(e.Key), aws.ToString(e.Message)))
		}
		if len(errs) > 0 {
			return errors.Join(errs...)
		}
	}
	// Markers go last and one at a time, deepest first.
	for _, d := range dirs {
		if err := s.deleteObject(ctx, d); err != nil {
			return err
		}
	}
	return nil
}

func (s *S3) deleteObject(ctx context.Context, key string) error {
	_, err := s.c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: s.bucket, Key: aws.String(key)})
	if err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func (s *S3) Delete(ctx context.Context, p string, recursive bool) error {
	if p == "" {
		return ErrInvalidPath
	}
	e, err := s.Stat(ctx, p)
	if err != nil {
		return err
	}
	if err := s.keepParent(ctx, p); err != nil {
		return err
	}
	if !e.IsDir {
		return s.deleteObject(ctx, p)
	}
	keys, err := s.walk(ctx, p+"/")
	if err != nil {
		return err
	}
	if !recursive && len(keys) > 1 {
		return ErrNotEmpty
	}
	return s.removeKeys(ctx, keys)
}

// copySource URL-encodes bucket/key. "+" is escaped because some servers
// decode it as a space.
func (s *S3) copySource(key string) *string {
	segs := strings.Split(key, "/")
	for i, seg := range segs {
		segs[i] = strings.ReplaceAll(url.PathEscape(seg), "+", "%2B")
	}
	return aws.String(aws.ToString(s.bucket) + "/" + strings.Join(segs, "/"))
}

func (s *S3) copyObject(ctx context.Context, src, dst string, size int64) error {
	if strings.HasSuffix(src, "/") {
		// Directory markers are recreated, some servers refuse to copy them.
		return s.putMarker(ctx, dst)
	}
	if size <= maxSingleCopy {
		_, err := s.c.CopyObject(ctx, &s3.CopyObjectInput{Bucket: s.bucket, Key: aws.String(dst), CopySource: s.copySource(src)})
		return err
	}
	// Objects over 5 GiB must be copied with UploadPartCopy.
	h, err := s.head(ctx, src)
	if err != nil {
		return err
	}
	mpu, err := s.c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: s.bucket, Key: aws.String(dst), ContentType: h.ContentType})
	if err != nil {
		return err
	}
	var parts []types.CompletedPart
	for off, num := int64(0), int32(1); off < size; off, num = off+copyPartSize, num+1 {
		end := min(off+copyPartSize, size) - 1
		out, err := s.c.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket: s.bucket, Key: aws.String(dst), UploadId: mpu.UploadId, PartNumber: aws.Int32(num),
			CopySource: s.copySource(src), CopySourceRange: aws.String(fmt.Sprintf("bytes=%d-%d", off, end)),
		})
		if err != nil {
			s.c.AbortMultipartUpload(context.WithoutCancel(ctx), &s3.AbortMultipartUploadInput{Bucket: s.bucket, Key: aws.String(dst), UploadId: mpu.UploadId})
			return err
		}
		parts = append(parts, types.CompletedPart{ETag: out.CopyPartResult.ETag, PartNumber: aws.Int32(num)})
	}
	_, err = s.c.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: s.bucket, Key: aws.String(dst), UploadId: mpu.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
	return err
}

// Move copies then deletes. It is not atomic for directories.
func (s *S3) Move(ctx context.Context, src, dst string) error {
	if src == "" || dst == "" || IsWithin(dst, src) {
		return ErrInvalidPath
	}
	e, err := s.Stat(ctx, src)
	if err != nil {
		return err
	}
	if _, err := s.Stat(ctx, dst); err == nil {
		return ErrExist
	} else if !errors.Is(err, ErrNotExist) {
		return err
	}
	if err := s.checkParents(ctx, dst); err != nil {
		return err
	}
	if err := s.keepParent(ctx, src); err != nil {
		return err
	}
	if !e.IsDir {
		if err := s.copyObject(ctx, src, dst, e.Size); err != nil {
			return err
		}
		return s.deleteObject(ctx, src)
	}
	keys, err := s.walk(ctx, src+"/")
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := s.copyObject(ctx, k.key, dst+"/"+strings.TrimPrefix(k.key, src+"/"), k.size); err != nil {
			return err
		}
	}
	return s.removeKeys(ctx, keys)
}
