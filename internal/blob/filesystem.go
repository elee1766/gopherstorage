package blob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
)

// Filesystem stores blobs in a directory. Access goes through os.Root.
type Filesystem struct {
	root *os.Root
}

func NewFilesystem(dir string) (*Filesystem, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if err := r.MkdirAll("tmp", 0o750); err != nil {
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

func (f *Filesystem) Put(_ context.Context, key string, r io.Reader, _ int64) error {
	if !validKey(key) {
		return errBadKey
	}
	var rnd [8]byte
	rand.Read(rnd[:])
	tmp := "tmp/" + hex.EncodeToString(rnd[:])
	fh, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	_, err = io.Copy(fh, r)
	if err == nil {
		err = fh.Sync()
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	dst := shard(key)
	if err == nil {
		err = f.root.MkdirAll(path.Dir(dst), 0o750)
	}
	if err == nil {
		err = f.root.Rename(tmp, dst)
	}
	if err != nil {
		f.root.Remove(tmp)
	}
	return err
}

func (f *Filesystem) Open(_ context.Context, key string, _ int64) (io.ReadSeekCloser, error) {
	if !validKey(key) {
		return nil, errBadKey
	}
	fh, err := f.root.Open(shard(key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	return fh, err
}

func (f *Filesystem) Delete(_ context.Context, key string) error {
	if !validKey(key) {
		return errBadKey
	}
	err := f.root.Remove(shard(key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
