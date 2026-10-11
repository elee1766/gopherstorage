package sqlite

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/elee1766/gopherstorage/pkg/meta"
)

func TestPerUserSessionAndOAuthCredentialCaps(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, t.TempDir()+"/meta.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "cap-user", Username: "capuser"})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < meta.MaxSessionsPerUser; i++ {
		if err := store.CreateSession(ctx, []byte(fmt.Sprintf("session-%d", i)), u.ID, "issuer", u.Sub, "", time.Hour); err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}
	}
	if err := store.CreateSession(ctx, []byte("session-over-cap"), u.ID, "issuer", u.Sub, "", time.Hour); !errors.Is(err, meta.ErrSessionLimit) {
		t.Fatalf("51st session error = %v, want meta.ErrSessionLimit", err)
	}

	var firstGrant int64
	for i := 0; i < meta.MaxOAuthGrantsPerUser; i++ {
		id, err := store.UpsertGrant(ctx, u.ID, fmt.Sprintf("https://app-%d.example", i), "app", "notes:r")
		if err != nil {
			t.Fatalf("create grant %d: %v", i, err)
		}
		if i == 0 {
			firstGrant = id
		}
	}
	if _, err := store.UpsertGrant(ctx, u.ID, "https://app-over-cap.example", "app", "notes:r"); !errors.Is(err, meta.ErrCredentialLimit) {
		t.Fatalf("101st grant error = %v, want meta.ErrCredentialLimit", err)
	}

	for i := 0; i < meta.MaxPendingAuthCodesPerUser; i++ {
		code := fmt.Sprintf("code-%d", i)
		if err := store.SaveAuthCode(ctx, code, meta.AuthCode{GrantID: firstGrant, RedirectURI: "https://app.example/cb", Scope: "notes:r", CodeChallenge: "challenge"}, time.Hour); err != nil {
			t.Fatalf("save auth code %d: %v", i, err)
		}
	}
	if err := store.SaveAuthCode(ctx, "code-over-cap", meta.AuthCode{GrantID: firstGrant}, time.Hour); !errors.Is(err, meta.ErrCredentialLimit) {
		t.Fatalf("33rd pending code error = %v, want meta.ErrCredentialLimit", err)
	}

	for i := 0; i < meta.MaxActiveCredentialsPerUser-meta.MaxPendingAuthCodesPerUser; i++ {
		if err := store.IssueToken(ctx, firstGrant, fmt.Sprintf("token-%d", i), "notes:r", time.Hour); err != nil {
			t.Fatalf("issue token %d: %v", i, err)
		}
	}
	if err := store.IssueToken(ctx, firstGrant, "token-over-cap", "notes:r", time.Hour); !errors.Is(err, meta.ErrCredentialLimit) {
		t.Fatalf("credential beyond combined cap error = %v, want meta.ErrCredentialLimit", err)
	}
}

func TestOIDCLogoutSessionMappingAndReplayPrevention(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, t.TempDir()+"/meta.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first, err := store.UpsertUser(ctx, meta.Login{Sub: "same-sub", Username: "first"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.UpsertUser(ctx, meta.Login{Sub: "other-sub", Username: "second"})
	if err != nil {
		t.Fatal(err)
	}
	firstSID := []byte("first-browser-session")
	otherSID := []byte("other-browser-session")
	secondUserSID := []byte("second-user-session")
	for _, s := range []struct {
		id     []byte
		userID int64
		sub    string
		sid    string
	}{
		{firstSID, first.ID, first.Sub, "sid-1"},
		{otherSID, first.ID, first.Sub, "sid-2"},
		{secondUserSID, second.ID, second.Sub, "sid-1"},
	} {
		if err := store.CreateSession(ctx, s.id, s.userID, "https://id.example", s.sub, s.sid, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	exp := time.Now().Add(5 * time.Minute)
	if err := store.RevokeOIDCLogout(ctx, "https://id.example", "jti-1", first.Sub, "sid-1", exp); err != nil {
		t.Fatal(err)
	}
	if valid, err := store.ValidSession(ctx, firstSID, first.ID); err != nil || valid {
		t.Fatalf("matching OIDC session valid=%v err=%v", valid, err)
	}
	if valid, err := store.ValidSession(ctx, otherSID, first.ID); err != nil || !valid {
		t.Fatalf("different sid of same subject valid=%v err=%v", valid, err)
	}
	if valid, err := store.ValidSession(ctx, secondUserSID, second.ID); err != nil || !valid {
		t.Fatalf("same sid of different subject valid=%v err=%v", valid, err)
	}
	if err := store.RevokeOIDCLogout(ctx, "https://id.example", "jti-1", second.Sub, "sid-1", exp); err == nil {
		t.Fatal("replayed logout token was accepted")
	}
	if valid, err := store.ValidSession(ctx, secondUserSID, second.ID); err != nil || !valid {
		t.Fatalf("replayed logout token revoked a session: valid=%v err=%v", valid, err)
	}
}
