package meta

import (
	"errors"

	"anime.bike/remotestorage/pkg/rs"
)

var (
	// ErrNotFound is returned for missing records where the operation maps absence to the metadata sentinel.
	ErrNotFound = errors.New("not found")
	// ErrReadOnly is returned when a write is attempted through a read-only store.
	ErrReadOnly = errors.New("metadata store is read-only")
	// ErrUsernameTaken reports a username owned by another account.
	ErrUsernameTaken = errors.New("username is used by another account")
	// ErrCredentialLimit reports a per-user OAuth grant or active credential cap.
	ErrCredentialLimit = errors.New("credential limit reached")
	// ErrSessionLimit reports that the active session cap has been reached.
	ErrSessionLimit = errors.New("too many active sessions")
	// ErrAccountDisabled reports an operation rejected for a disabled account.
	ErrAccountDisabled = errors.New("account is disabled")
	// ErrTokenLimit reports that the personal API-token cap has been reached.
	ErrTokenLimit = errors.New("too many API tokens")
	// ErrUploadCapacity is the shared protocol quota error for upload capacity failures.
	ErrUploadCapacity = rs.ErrQuotaExceeded
)
