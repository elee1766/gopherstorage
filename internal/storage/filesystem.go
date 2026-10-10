package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
)

const tmpPrefix = ".gopherstorage-tmp-"

// Filesystem stores files in a local directory. All access goes through
// os.Root, so symlinks cannot escape the directory.
type Filesystem struct {
	root *os.Root
}

func NewFilesystem(dir string) (*Filesystem, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Filesystem{root: r}, nil
}

func (f *Filesystem) Close() error { return f.root.Close() }

func rel(p string) string {
	if p == "" {
		return "."
	}
	return p
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ENOTEMPTY):
		return fmt.Errorf("%w: %v", ErrNotEmpty, err)
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: %v", ErrNotExist, err)
	case errors.Is(err, fs.ErrExist):
		return fmt.Errorf("%w: %v", ErrExist, err)
	case errors.Is(err, syscall.ENOTDIR):
		return fmt.Errorf("%w: %v", ErrNotDir, err)
	case errors.Is(err, syscall.EISDIR):
		return fmt.Errorf("%w: %v", ErrIsDir, err)
	}
	return err
}

func fileEntry(p string, fi fs.FileInfo) Entry {
	e := Entry{Name: fi.Name(), Path: p, IsDir: fi.IsDir(), ModTime: fi.ModTime().UTC()}
	if p == "" {
		e.Name = ""
	}
	if !e.IsDir {
		e.Size = fi.Size()
		e.ContentType = mime.TypeByExtension(path.Ext(p))
	}
	return e
}

func (f *Filesystem) Stat(_ context.Context, p string) (Entry, error) {
	fi, err := f.root.Stat(rel(p))
	if err != nil {
		return Entry{}, mapErr(err)
	}
	return fileEntry(p, fi), nil
}

func (f *Filesystem) List(_ context.Context, dir string) ([]Entry, error) {
	d, err := f.root.Open(rel(dir))
	if err != nil {
		return nil, mapErr(err)
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil {
		return nil, mapErr(err)
	}
	if !fi.IsDir() {
		return nil, ErrNotDir
	}
	names, err := d.Readdirnames(-1)
	if err != nil {
		return nil, mapErr(err)
	}
	sort.Strings(names)
	out := make([]Entry, 0, len(names))
	for _, name := range names {
		if strings.HasPrefix(name, tmpPrefix) {
			continue
		}
		p := Join(dir, name)
		// Stat follows symlinks; broken or escaping links are skipped.
		fi, err := f.root.Stat(p)
		if err != nil {
			continue
		}
		out = append(out, fileEntry(p, fi))
	}
	return out, nil
}

func (f *Filesystem) Open(_ context.Context, p string) (io.ReadSeekCloser, Entry, error) {
	fh, err := f.root.Open(rel(p))
	if err != nil {
		return nil, Entry{}, mapErr(err)
	}
	fi, err := fh.Stat()
	if err != nil {
		fh.Close()
		return nil, Entry{}, mapErr(err)
	}
	if fi.IsDir() {
		fh.Close()
		return nil, Entry{}, ErrIsDir
	}
	return fh, fileEntry(p, fi), nil
}

func (f *Filesystem) Put(ctx context.Context, p string, r io.Reader, _ int64, _ string) (Entry, error) {
	if p == "" {
		return Entry{}, ErrIsDir
	}
	if fi, err := f.root.Stat(p); err == nil && fi.IsDir() {
		return Entry{}, ErrIsDir
	}
	dir := path.Dir(p)
	if dir == "." {
		dir = ""
	}
	if err := f.Mkdir(ctx, dir); errors.Is(err, ErrExist) {
		return Entry{}, ErrNotDir
	} else if err != nil {
		return Entry{}, err
	}
	var rnd [8]byte
	rand.Read(rnd[:])
	tmp := Join(dir, tmpPrefix+hex.EncodeToString(rnd[:]))
	fh, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return Entry{}, mapErr(err)
	}
	_, err = io.Copy(fh, r)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = f.root.Rename(tmp, p)
	}
	if err != nil {
		f.root.Remove(tmp)
		return Entry{}, mapErr(err)
	}
	return f.Stat(ctx, p)
}

func (f *Filesystem) Mkdir(_ context.Context, p string) error {
	if p == "" {
		return nil
	}
	if err := f.root.MkdirAll(p, 0o755); err != nil {
		if fi, serr := f.root.Stat(p); serr == nil && !fi.IsDir() {
			return ErrExist
		}
		for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
			if fi, serr := f.root.Stat(dir); serr == nil && !fi.IsDir() {
				return ErrNotDir
			}
		}
		return mapErr(err)
	}
	return nil
}

func (f *Filesystem) Delete(_ context.Context, p string, recursive bool) error {
	if p == "" {
		return ErrInvalidPath
	}
	fi, err := f.root.Lstat(p)
	if err != nil {
		return mapErr(err)
	}
	if fi.IsDir() && recursive {
		return mapErr(f.root.RemoveAll(p))
	}
	return mapErr(f.root.Remove(p))
}

func (f *Filesystem) Move(_ context.Context, src, dst string) error {
	if src == "" || dst == "" || IsWithin(dst, src) {
		return ErrInvalidPath
	}
	if _, err := f.root.Lstat(src); err != nil {
		return mapErr(err)
	}
	if _, err := f.root.Lstat(dst); err == nil {
		return ErrExist
	}
	if dir := path.Dir(dst); dir != "." {
		if err := f.Mkdir(context.Background(), dir); errors.Is(err, ErrExist) {
			return ErrNotDir
		} else if err != nil {
			return err
		}
	}
	return mapErr(f.root.Rename(src, dst))
}
