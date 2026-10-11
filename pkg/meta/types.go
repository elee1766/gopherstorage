// Package meta defines backend-neutral metadata types and store capabilities.
package meta

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
)

// User is an account, created on first login.
type User struct {
	ID         int64
	Sub        string
	Username   string
	Email      string
	QuotaBytes int64
	UsedBytes  int64
	CreatedAt  time.Time
	LastLogin  time.Time
	// IsAdmin reflects the OIDC groups at the last login.
	IsAdmin  bool
	Disabled bool
}

// Login is what an OIDC login tells us about a user.
type Login struct {
	Sub, Username, Email string
	IsAdmin              bool
}

// Node is a document or a non-empty folder.
type Node struct {
	Path        string
	IsFolder    bool
	ETag        string
	ContentType string
	Size        int64
	BlobKey     string
	Modified    time.Time
}

// Metadata converts a node to the remoteStorage metadata type.
func (n *Node) Metadata() rs.Metadata {
	return rs.Metadata{Path: n.Path, Name: rs.BaseName(n.Path), IsFolder: n.IsFolder, ETag: n.ETag, ContentType: n.ContentType, Size: n.Size, LastModified: n.Modified}
}

// PutDocument is the input to Store.PutDocument.
type PutDocument struct {
	UserID      int64
	Path        string
	ContentType string
	Size        int64
	BlobKey     string
	// ETag is the new version tag. Content hashes make retries idempotent.
	ETag              string
	Cond              rsserver.Condition
	Quota             int64 // effective quota in bytes, 0 = unlimited
	MaxNodes          int64
	MaxFolderChildren int
}

// PutResult describes a successful PutDocument.
type PutResult struct {
	ETag    string
	Created bool
	// OldBlobKey is the replaced document's blob, now orphaned.
	OldBlobKey string
}

// DeleteResult describes a successful DeleteDocument.
type DeleteResult struct {
	ETag    string
	BlobKey string
}

// PendingBlob is a blob that may need deleting.
type PendingBlob struct {
	Key       string
	Reason    string
	CreatedAt time.Time
}

// Grant is an app a user has authorized.
type Grant struct {
	ID         int64
	UserID     int64
	ClientID   string
	ClientName string
	Scope      string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// TokenInfo is what a valid bearer token grants.
type TokenInfo struct {
	UserID   int64
	Username string
	GrantID  int64
	Scope    string
}

// AuthCode is a pending PKCE authorization code.
type AuthCode struct {
	GrantID       int64
	RedirectURI   string
	Scope         string
	CodeChallenge string
}

// APIToken is a personal token for the account API.
type APIToken struct {
	ID         int64
	UserID     int64
	Name       string
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time // zero means no expiry
}

const (
	MaxOAuthGrantsPerUser       = 100
	MaxActiveCredentialsPerUser = 256
	MaxPendingAuthCodesPerUser  = 32
	MaxSessionsPerUser          = 50
	MaxAPITokens                = 50
)

// NewBlobKey returns a fresh random blob key.
func NewBlobKey() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
