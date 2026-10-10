// Package blob stores immutable document contents by key.
// Keys are random hex strings; a blob is never modified after Put.
package blob

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound is returned for missing blobs.
var ErrNotFound = errors.New("blob not found")

// Store is a blob backend.
type Store interface {
	// Put stores r under key. size is -1 if unknown.
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	// Open returns a reader that supports Seek, for range requests.
	Open(ctx context.Context, key string, size int64) (io.ReadSeekCloser, error)
	// Delete removes a blob. Missing blobs are not an error.
	Delete(ctx context.Context, key string) error
}

// shard spreads keys over subdirectories / prefixes: "ab/cd/abcd...".
func shard(key string) string {
	if len(key) < 4 {
		return key
	}
	return key[:2] + "/" + key[2:4] + "/" + key
}
