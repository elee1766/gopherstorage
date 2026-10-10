// Package storage defines the backend interface used by the server.
//
// Paths are slash separated, relative, and already cleaned by Clean.
// The empty string refers to the backend root.
package storage

import (
	"context"
	"errors"
	"io"
	"path"
	"strings"
	"time"
)

var (
	ErrNotExist    = errors.New("not found")
	ErrExist       = errors.New("already exists")
	ErrIsDir       = errors.New("is a directory")
	ErrNotDir      = errors.New("not a directory")
	ErrNotEmpty    = errors.New("directory not empty")
	ErrInvalidPath = errors.New("invalid path")
)

type Entry struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	IsDir       bool      `json:"is_dir"`
	Size        int64     `json:"size"`
	ModTime     time.Time `json:"mod_time,omitzero"`
	ContentType string    `json:"content_type,omitempty"`
	ETag        string    `json:"etag,omitempty"`
}

type Backend interface {
	Stat(ctx context.Context, p string) (Entry, error)
	// List returns the direct children of dir, sorted by name.
	List(ctx context.Context, dir string) ([]Entry, error)
	Open(ctx context.Context, p string) (io.ReadSeekCloser, Entry, error)
	// Put writes a file, creating parent directories. size may be -1 if unknown.
	Put(ctx context.Context, p string, r io.Reader, size int64, contentType string) (Entry, error)
	// Mkdir creates a directory and its parents. It succeeds if it already exists.
	Mkdir(ctx context.Context, p string) error
	// Delete removes a file or directory. Non-empty directories need recursive.
	Delete(ctx context.Context, p string, recursive bool) error
	// Move renames a file or directory. dst must not exist.
	Move(ctx context.Context, src, dst string) error
}

// Clean normalizes a user supplied path and rejects traversal.
func Clean(p string) (string, error) {
	if strings.ContainsRune(p, 0) || strings.Contains(p, "\\") {
		return "", ErrInvalidPath
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", ErrInvalidPath
		}
	}
	c := path.Clean("/" + p)
	if c == "/" {
		return "", nil
	}
	return c[1:], nil
}

// Join joins cleaned path elements, skipping empty ones.
func Join(elems ...string) string {
	var parts []string
	for _, e := range elems {
		if e = strings.Trim(e, "/"); e != "" {
			parts = append(parts, e)
		}
	}
	return strings.Join(parts, "/")
}

// IsWithin reports whether p equals dir or is beneath it.
func IsWithin(p, dir string) bool {
	return dir == "" || p == dir || strings.HasPrefix(p, dir+"/")
}

// Prefixed scopes a backend to a subdirectory.
func Prefixed(b Backend, prefix string) Backend {
	if prefix == "" {
		return b
	}
	return &prefixed{b: b, prefix: prefix}
}

type prefixed struct {
	b      Backend
	prefix string
}

func (p *prefixed) full(s string) string { return Join(p.prefix, s) }

func (p *prefixed) strip(e Entry) Entry {
	e.Path = strings.TrimPrefix(strings.TrimPrefix(e.Path, p.prefix), "/")
	return e
}

func (p *prefixed) Stat(ctx context.Context, s string) (Entry, error) {
	e, err := p.b.Stat(ctx, p.full(s))
	return p.strip(e), err
}

func (p *prefixed) List(ctx context.Context, dir string) ([]Entry, error) {
	es, err := p.b.List(ctx, p.full(dir))
	for i := range es {
		es[i] = p.strip(es[i])
	}
	return es, err
}

func (p *prefixed) Open(ctx context.Context, s string) (io.ReadSeekCloser, Entry, error) {
	r, e, err := p.b.Open(ctx, p.full(s))
	return r, p.strip(e), err
}

func (p *prefixed) Put(ctx context.Context, s string, r io.Reader, size int64, ct string) (Entry, error) {
	e, err := p.b.Put(ctx, p.full(s), r, size, ct)
	return p.strip(e), err
}

func (p *prefixed) Mkdir(ctx context.Context, s string) error { return p.b.Mkdir(ctx, p.full(s)) }

// The root of a prefixed view cannot be deleted or moved.
func (p *prefixed) Delete(ctx context.Context, s string, recursive bool) error {
	if s == "" {
		return ErrInvalidPath
	}
	return p.b.Delete(ctx, p.full(s), recursive)
}

func (p *prefixed) Move(ctx context.Context, src, dst string) error {
	if src == "" || dst == "" {
		return ErrInvalidPath
	}
	return p.b.Move(ctx, p.full(src), p.full(dst))
}
