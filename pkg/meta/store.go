package meta

import (
	"context"
	"time"

	"anime.bike/remotestorage/pkg/rsserver"
)

// Store composes the metadata capabilities required by the application.
type Store interface {
	Users
	Documents
	OAuth
	APITokens
	Sessions
	Maintenance
}

// Users manages accounts and quotas.
type Users interface {
	UpsertUser(ctx context.Context, login Login) (*User, error)
	UserByName(ctx context.Context, username string) (*User, error)
	UserByID(ctx context.Context, id int64) (*User, error)
	UserBySub(ctx context.Context, sub string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	SetQuota(ctx context.Context, userID, quota int64) error
}

// Documents manages the document tree and blob publication lifecycle.
type Documents interface {
	GetNode(ctx context.Context, userID int64, path string) (*Node, error)
	ListFolder(ctx context.Context, userID int64, folder string) (*Node, []*Node, error)
	// ListFolderLimit returns no partial children when the limit is exceeded.
	// A missing folder returns (nil, nil, nil).
	ListFolderLimit(ctx context.Context, userID int64, folder string, limit int) (*Node, []*Node, error)
	// PutDocument atomically consumes the matching upload reservation, claims
	// its upload blob for publication, updates the node and usage, and records
	// the replaced blob as an orphan. It conflicts if collection already claimed
	// the blob or the reservation does not match.
	PutDocument(ctx context.Context, in PutDocument) (*PutResult, error)
	DeleteDocument(ctx context.Context, userID int64, path string, cond rsserver.Condition) (*DeleteResult, error)
	Usage(ctx context.Context, userID int64) (docs, bytes int64, err error)
	ListPublic(ctx context.Context, userID int64, limit int) ([]*Node, error)
}

// OAuth manages grants, bearer tokens, and one-time authorization codes.
type OAuth interface {
	UpsertGrant(ctx context.Context, userID int64, clientID, clientName, scope string) (int64, error)
	IssueToken(ctx context.Context, grantID int64, token, scope string, ttl time.Duration) error
	LookupToken(ctx context.Context, token string) (*TokenInfo, error)
	TouchGrant(ctx context.Context, grantID int64) error
	ListGrants(ctx context.Context, userID int64) ([]*Grant, error)
	RevokeGrant(ctx context.Context, userID, grantID int64) error
	SaveAuthCode(ctx context.Context, code string, authCode AuthCode, ttl time.Duration) error
	// RedeemAuthCode atomically removes and returns an unexpired code. A code
	// can be redeemed successfully at most once.
	RedeemAuthCode(ctx context.Context, code string) (*AuthCode, error)
	GrantUser(ctx context.Context, grantID int64) (userID int64, clientID string, err error)
}

// APITokens manages personal API tokens.
type APITokens interface {
	CreateAPIToken(ctx context.Context, userID int64, name, token string, ttl time.Duration) (*APIToken, error)
	LookupAPIToken(ctx context.Context, token string) (*APIToken, *User, error)
	ListAPITokens(ctx context.Context, userID int64) ([]*APIToken, error)
	DeleteAPIToken(ctx context.Context, userID, id int64) error
}

// Sessions manages browser sessions and account credential revocation.
type Sessions interface {
	CreateSession(ctx context.Context, id []byte, userID int64, issuer, subject, oidcSID string, ttl time.Duration) error
	ValidSession(ctx context.Context, id []byte, userID int64) (bool, error)
	RevokeSession(ctx context.Context, id []byte) error
	// SetUserDisabled commits the disabled state and credential revocations as
	// one operation. Re-enabling does not restore previously revoked credentials.
	SetUserDisabled(ctx context.Context, userID int64, disabled bool) error
	// RevokeUserCredentials removes all local credentials without changing the
	// user's disabled state.
	RevokeUserCredentials(ctx context.Context, userID int64) error
	// RevokeOIDCLogout atomically records replay protection and applies the
	// matching session or subject-wide credential revocations.
	RevokeOIDCLogout(ctx context.Context, issuer, jti, subject, sid string, replayUntil time.Time) error
}

// Maintenance provides upload reservations, blob garbage collection, expiry cleanup, and store shutdown.
type Maintenance interface {
	// ReserveUpload atomically reserves per-user and global staging capacity,
	// and records the blob key before upload. A successful reservation must be
	// used by PutDocument to publish that blob.
	ReserveUpload(ctx context.Context, userID int64, path, blobKey string, reserveBytes, quota int64, maxInFlight int, maxStagingBytes int64, maxFolderChildren int, clamp bool) (reservedBytes int64, err error)
	// AddPendingBlob records a blob for garbage collection tracking. It does not
	// create a publication reservation, so it cannot satisfy PutDocument.
	AddPendingBlob(ctx context.Context, key string) error
	// CollectableBlobs atomically claims unreferenced candidates by changing
	// their reason to "collecting". Publishers must reject claimed blobs, and
	// callers should delete only the returned claims before calling ForgetBlob.
	CollectableBlobs(ctx context.Context, uploadGrace time.Duration, limit int) ([]PendingBlob, error)
	// ForgetBlob removes an unreferenced pending entry after blob-store deletion.
	ForgetBlob(ctx context.Context, key string) error
	PruneExpired(ctx context.Context) error
	Close() error
}
