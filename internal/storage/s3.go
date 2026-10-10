package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3 stores files in an S3 compatible bucket. Directories are key prefixes.
// Empty directories are kept with a zero byte "dir/" marker object.
type S3 struct {
	c      *minio.Client
	bucket string
}

type S3Options struct {
	Endpoint     string
	Region       string
	Bucket       string
	AccessKey    string
	SecretKey    string
	SessionToken string
	Insecure     bool
	PathStyle    bool
}

const maxSingleCopy = 5 << 30

func NewS3(ctx context.Context, o S3Options) (*S3, error) {
	endpoint := o.Endpoint
	secure := !o.Insecure
	// Accept endpoints given as URLs.
	if rest, ok := strings.CutPrefix(endpoint, "https://"); ok {
		endpoint, secure = rest, true
	} else if rest, ok := strings.CutPrefix(endpoint, "http://"); ok {
		endpoint, secure = rest, false
	}
	endpoint = strings.TrimRight(endpoint, "/")
	var creds *credentials.Credentials
	if o.AccessKey != "" {
		creds = credentials.NewStaticV4(o.AccessKey, o.SecretKey, o.SessionToken)
	} else {
		creds = credentials.NewChainCredentials([]credentials.Provider{
			&credentials.EnvAWS{}, &credentials.FileAWSCredentials{}, &credentials.IAM{},
		})
	}
	lookup := minio.BucketLookupAuto
	if o.PathStyle {
		lookup = minio.BucketLookupPath
	}
	c, err := minio.New(endpoint, &minio.Options{Creds: creds, Secure: secure, Region: o.Region, BucketLookup: lookup})
	if err != nil {
		return nil, err
	}
	ok, err := c.BucketExists(ctx, o.Bucket)
	if err != nil {
		return nil, fmt.Errorf("check bucket %q: %w", o.Bucket, err)
	}
	if !ok {
		return nil, fmt.Errorf("bucket %q does not exist", o.Bucket)
	}
	return &S3{c: c, bucket: o.Bucket}, nil
}

func isNoSuchKey(err error) bool {
	r := minio.ToErrorResponse(err)
	return r.Code == minio.NoSuchKey || r.StatusCode == http.StatusNotFound
}

func objEntry(p string, oi minio.ObjectInfo) Entry {
	e := Entry{Name: path.Base(p), Path: p, Size: oi.Size, ModTime: oi.LastModified.UTC(), ETag: oi.ETag, ContentType: oi.ContentType}
	if e.ContentType == "" || e.ContentType == "application/octet-stream" {
		if ct := mime.TypeByExtension(path.Ext(p)); ct != "" {
			e.ContentType = ct
		}
	}
	return e
}

func dirEntry(p string) Entry {
	e := Entry{Name: path.Base(p), Path: p, IsDir: true}
	if p == "" {
		e.Name = ""
	}
	return e
}

// dirExists reports whether any object has the prefix p/.
func (s *S3) dirExists(ctx context.Context, p string) (bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for oi := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: p + "/", MaxKeys: 1}) {
		if oi.Err != nil {
			return false, oi.Err
		}
		return true, nil
	}
	return false, nil
}

func (s *S3) Stat(ctx context.Context, p string) (Entry, error) {
	if p == "" {
		return dirEntry(""), nil
	}
	oi, err := s.c.StatObject(ctx, s.bucket, p, minio.StatObjectOptions{})
	if err == nil {
		return objEntry(p, oi), nil
	}
	if !isNoSuchKey(err) {
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

func (s *S3) List(ctx context.Context, dir string) ([]Entry, error) {
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	var out []Entry
	found := dir == ""
	for oi := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix}) {
		if oi.Err != nil {
			return nil, oi.Err
		}
		found = true
		if oi.Key == prefix {
			continue // directory marker
		}
		name := strings.TrimPrefix(oi.Key, prefix)
		if strings.HasSuffix(name, "/") {
			out = append(out, dirEntry(Join(dir, strings.TrimSuffix(name, "/"))))
			continue
		}
		out = append(out, objEntry(Join(dir, name), oi))
	}
	if !found {
		if e, err := s.Stat(ctx, dir); err == nil && !e.IsDir {
			return nil, ErrNotDir
		}
		return nil, ErrNotExist
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *S3) Open(ctx context.Context, p string) (io.ReadSeekCloser, Entry, error) {
	if p == "" {
		return nil, Entry{}, ErrIsDir
	}
	oi, err := s.c.StatObject(ctx, s.bucket, p, minio.StatObjectOptions{})
	if err != nil {
		if isNoSuchKey(err) {
			if ok, _ := s.dirExists(ctx, p); ok {
				return nil, Entry{}, ErrIsDir
			}
			return nil, Entry{}, ErrNotExist
		}
		return nil, Entry{}, err
	}
	obj, err := s.c.GetObject(ctx, s.bucket, p, minio.GetObjectOptions{})
	if err != nil {
		return nil, Entry{}, err
	}
	return obj, objEntry(p, oi), nil
}

// checkParents fails if any ancestor of p is a regular file.
func (s *S3) checkParents(ctx context.Context, p string) error {
	for dir := path.Dir(p); dir != "." && dir != "/"; dir = path.Dir(dir) {
		_, err := s.c.StatObject(ctx, s.bucket, dir, minio.StatObjectOptions{})
		if err == nil {
			return ErrNotDir
		}
		if !isNoSuchKey(err) {
			return err
		}
	}
	return nil
}

func (s *S3) Put(ctx context.Context, p string, r io.Reader, size int64, contentType string) (Entry, error) {
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
	if contentType == "" {
		contentType = mime.TypeByExtension(path.Ext(p))
	}
	opts := minio.PutObjectOptions{ContentType: contentType}
	if size < 0 {
		// Bound the buffer used for streams of unknown length. Max object size becomes 160 GiB.
		opts.PartSize = 16 << 20
	}
	if _, err := s.c.PutObject(ctx, s.bucket, p, r, size, opts); err != nil {
		return Entry{}, err
	}
	return s.Stat(ctx, p)
}

func (s *S3) Mkdir(ctx context.Context, p string) error {
	if p == "" {
		return nil
	}
	_, err := s.c.StatObject(ctx, s.bucket, p, minio.StatObjectOptions{})
	if err == nil {
		return ErrExist
	}
	if !isNoSuchKey(err) {
		return err
	}
	if err := s.checkParents(ctx, p); err != nil {
		return err
	}
	_, err = s.c.PutObject(ctx, s.bucket, p+"/", strings.NewReader(""), 0, minio.PutObjectOptions{ContentType: "application/x-directory"})
	return err
}

// keepParent writes a marker for the parent of p so it survives removal of its last child.
func (s *S3) keepParent(ctx context.Context, p string) error {
	dir := path.Dir(p)
	if dir == "." || dir == "/" {
		return nil
	}
	_, err := s.c.PutObject(ctx, s.bucket, dir+"/", strings.NewReader(""), 0, minio.PutObjectOptions{ContentType: "application/x-directory"})
	return err
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
	var out []s3Key
	for oi := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix}) {
		if oi.Err != nil {
			return nil, oi.Err
		}
		if oi.Key == prefix {
			continue
		}
		if strings.HasSuffix(oi.Key, "/") {
			sub, err := s.walk(ctx, oi.Key)
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
			continue
		}
		out = append(out, s3Key{key: oi.Key, size: oi.Size})
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
	if err := s.removeBatch(ctx, files); err != nil {
		return err
	}
	// Markers go last and one at a time, deepest first.
	for _, d := range dirs {
		if err := s.c.RemoveObject(ctx, s.bucket, d, minio.RemoveObjectOptions{}); err != nil && !isNoSuchKey(err) {
			return err
		}
	}
	return nil
}

func (s *S3) removeBatch(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	ch := make(chan minio.ObjectInfo)
	go func() {
		defer close(ch)
		for _, k := range keys {
			select {
			case ch <- minio.ObjectInfo{Key: k}:
			case <-ctx.Done():
				return
			}
		}
	}()
	var errs []error
	for e := range s.c.RemoveObjects(ctx, s.bucket, ch, minio.RemoveObjectsOptions{}) {
		errs = append(errs, fmt.Errorf("remove %s: %w", e.ObjectName, e.Err))
	}
	return errors.Join(errs...)
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
		return s.c.RemoveObject(ctx, s.bucket, p, minio.RemoveObjectOptions{})
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

func (s *S3) copyObject(ctx context.Context, src, dst string, size int64) error {
	if strings.HasSuffix(src, "/") {
		// Directory markers are recreated, some servers refuse to copy them.
		_, err := s.c.PutObject(ctx, s.bucket, dst, strings.NewReader(""), 0, minio.PutObjectOptions{ContentType: "application/x-directory"})
		return err
	}
	d := minio.CopyDestOptions{Bucket: s.bucket, Object: dst}
	sr := minio.CopySrcOptions{Bucket: s.bucket, Object: src}
	if size > maxSingleCopy {
		_, err := s.c.ComposeObject(ctx, d, sr)
		return err
	}
	_, err := s.c.CopyObject(ctx, d, sr)
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
		return s.c.RemoveObject(ctx, s.bucket, src, minio.RemoveObjectOptions{})
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
