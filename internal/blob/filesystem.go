package blob

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"time"
)

// Filesystem stores blobs in a directory. Access goes through os.Root.
type Filesystem struct {
	root *os.Root
}

func NewFilesystem(dir string) (*Filesystem, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if err := r.Chmod(".", 0o700); err != nil {
		r.Close()
		return nil, err
	}
	if err := r.MkdirAll("tmp", 0o700); err != nil {
		r.Close()
		return nil, err
	}
	if err := r.Chmod("tmp", 0o700); err != nil {
		r.Close()
		return nil, err
	}
	return &Filesystem{root: r}, nil
}

func (f *Filesystem) Close() error { return f.root.Close() }

func validKey(key string) bool {
	if len(key) < 4 || len(key) > 128 {
		return false
	}
	for _, c := range key {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

var errBadKey = errors.New("invalid blob key")

func (f *Filesystem) Put(ctx context.Context, key string, r io.Reader, _ int64) error {
	if !validKey(key) {
		return errBadKey
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The pending blob key also names partial bytes, so crash GC can find them.
	tmp := "tmp/" + key
	fh, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(fh, contextReader{ctx: ctx, r: r})
	if err == nil {
		err = fh.Sync()
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	dst := shard(key)
	if err == nil {
		err = f.root.MkdirAll(path.Dir(dst), 0o700)
	}
	if err == nil {
		err = f.root.Rename(tmp, dst)
	}
	if err != nil {
		f.root.Remove(tmp)
	}
	return err
}

func (f *Filesystem) Open(ctx context.Context, key string, _ int64) (io.ReadSeekCloser, error) {
	if !validKey(key) {
		return nil, errBadKey
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fh, err := f.root.Open(shard(key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	return fh, err
}

func (f *Filesystem) Delete(ctx context.Context, key string) error {
	if !validKey(key) {
		return errBadKey
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	remove := func(p string) error {
		err := f.root.Remove(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return errors.Join(remove("tmp/"+key), remove(shard(key)))
}

// CleanupTemporary removes aged pre-migration temporary files with no blob key.
func (f *Filesystem) CleanupTemporary(ctx context.Context, age time.Duration) (int, error) {
	if age <= 0 {
		return 0, errors.New("temporary cleanup age must be positive")
	}
	dir, err := f.root.Open("tmp")
	if err != nil {
		return 0, err
	}
	defer dir.Close()
	cutoff := time.Now().Add(-age)
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		entries, err := dir.ReadDir(128)
		for _, e := range entries {
			// New 32-character names have pending metadata and use normal GC.
			if len(e.Name()) != 16 || !validKey(e.Name()) {
				continue
			}
			st, err := e.Info()
			if err != nil {
				return total, err
			}
			if st.Mode().IsRegular() && st.ModTime().Before(cutoff) {
				if err := f.root.Remove("tmp/" + e.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return total, err
				}
				total++
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
