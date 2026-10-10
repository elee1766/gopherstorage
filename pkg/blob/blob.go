// Package blob stores immutable document contents by key.
// Keys are random hex strings; a blob is never modified after Put.
package blob

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
)

// ErrNotFound is returned for missing blobs.
var ErrNotFound = errors.New("blob not found")

// ErrTooLarge reports a blob larger than the backend's supported maximum.
var ErrTooLarge = errors.New("blob too large")

var (
	ErrInvalidKey       = errors.New("invalid blob key")
	ErrInvalidShardPath = errors.New("invalid blob shard path")
)

// Option configures a blob store. Options are applied at construction time.
type Option func(*storeOptions)

type storeOptions struct {
	sharder func(string) string
}

// WithSharder sets the function that maps a blob key to its relative object path.
// The returned path must end in the unchanged key. The function must be
// deterministic and safe for concurrent use. A nil function selects DefaultShard.
func WithSharder(sharder func(string) string) Option {
	return func(o *storeOptions) { o.sharder = sharder }
}

func applyOptions(opts []Option) storeOptions {
	var o storeOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if o.sharder == nil {
		o.sharder = DefaultShard
	}
	return o
}

// KeyMapper resolves blob keys to safe relative object paths.
type KeyMapper struct {
	sharder func(string) string
}

// NewKeyMapper builds a key mapper from store options. Options are resolved once.
func NewKeyMapper(opts ...Option) *KeyMapper {
	return &KeyMapper{sharder: applyOptions(opts).sharder}
}

// Path validates key and returns its relative object path.
func (m *KeyMapper) Path(key string) (string, error) {
	if !ValidKey(key) {
		return "", ErrInvalidKey
	}
	sharder := m.sharder
	if sharder == nil {
		sharder = DefaultShard
	}
	p := sharder(key)
	first, _, _ := strings.Cut(p, "/")
	if !fs.ValidPath(p) || !filepath.IsLocal(filepath.FromSlash(p)) || strings.ContainsAny(p, "\\\x00:") || path.Base(p) != key || strings.EqualFold(first, "tmp") {
		return "", ErrInvalidShardPath
	}
	return p, nil
}

// Store is a blob backend.
type Store interface {
	// Put stores r under key. size is -1 if unknown.
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	// Open returns a reader that supports Seek, for range requests.
	Open(ctx context.Context, key string, size int64) (io.ReadSeekCloser, error)
	// Delete removes a blob. Missing blobs are not an error.
	Delete(ctx context.Context, key string) error
}

// ValidKey reports whether key is a lowercase hexadecimal blob key.
func ValidKey(key string) bool {
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

// DefaultShard spreads keys over subdirectories / prefixes: "ab/cd/abcd...".
func DefaultShard(key string) string {
	if len(key) < 4 {
		return key
	}
	return key[:2] + "/" + key[2:4] + "/" + key
}
