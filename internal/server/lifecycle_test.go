package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elee1766/gopherstorage/internal/auth"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/meta"
	"github.com/elee1766/gopherstorage/internal/oauth"
	"github.com/elee1766/gopherstorage/internal/storage"
)

func TestAdminOffboardingRevokesPersistedCredentialsAndCopiedSessions(t *testing.T) {
	ctx := context.Background()
	dbPath := t.TempDir() + "/meta.db"
	store, err := meta.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := &config.Config{PublicURL: "https://storage.example", Session: config.Session{Secret: strings.Repeat("k", 32), MaxAge: time.Hour}}
	a, err := auth.NewSessionsOnly(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := store.UpsertUser(ctx, meta.Login{Sub: "oidc-alice", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.UpsertUser(ctx, meta.Login{Sub: "oidc-admin", Username: "admin", IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	grantID, err := store.UpsertGrant(ctx, alice.ID, "https://app.example", "app", "notes:rw")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.IssueToken(ctx, grantID, "oauth-secret", "notes:rw", 0); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, "authcode-secret", meta.AuthCode{GrantID: grantID, RedirectURI: "https://app.example/cb", Scope: "notes:rw", CodeChallenge: "challenge"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAPIToken(ctx, alice.ID, "test", "gsk_secret", 0); err != nil {
		t.Fatal(err)
	}
	aliceCookie, err := a.SessionCookie(&auth.Session{UserID: alice.ID, Username: alice.Username})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAPIToken(ctx, admin.ID, "admin", "gsk_admin-secret", 0); err != nil {
		t.Fatal(err)
	}
	s := New(cfg, store, &storage.Service{Meta: store}, a, &oauth.Server{Auth: a, Store: store, CSRFKey: []byte("csrf")})
	h := s.Handler()
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://storage.example"+path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if method == http.MethodPut {
			r.Header.Set("Authorization", "Bearer gsk_admin-secret")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET last_login=? WHERE id=?`, time.Now().Add(-16*time.Minute).Unix(), admin.ID); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodPut, "/api/v1/admin/users/"+intString(alice.ID)+"/access", `{"disabled":true}`, nil); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "sign in again") {
		t.Fatalf("stale admin access: %d %s", w.Code, w.Body.String())
	}
	if _, err := store.UpsertUser(ctx, meta.Login{Sub: admin.Sub, Username: admin.Username, IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodPut, "/api/v1/admin/users/"+intString(admin.ID)+"/access", `{"disabled":true}`, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("self-disable: %d %s", w.Code, w.Body.String())
	}
	if w := request(http.MethodPut, "/api/v1/admin/users/"+intString(alice.ID)+"/access", `{"disabled":true}`, nil); w.Code != http.StatusOK {
		t.Fatalf("disable API: %d %s", w.Code, w.Body.String())
	}
	cookieReq := httptest.NewRequest(http.MethodGet, "https://storage.example/", nil)
	cookieReq.AddCookie(aliceCookie)
	if got := a.Current(cookieReq); got != nil {
		t.Fatalf("copied session remains valid after offboarding: %+v", got)
	}
	if _, _, err := store.LookupAPIToken(ctx, "gsk_secret"); !errors.Is(err, meta.ErrNotFound) {
		t.Fatalf("API token survived offboarding: %v", err)
	}
	if _, err := store.LookupToken(ctx, "oauth-secret"); !errors.Is(err, meta.ErrNotFound) {
		t.Fatalf("OAuth token survived offboarding: %v", err)
	}
	if _, err := store.RedeemAuthCode(ctx, "authcode-secret"); !errors.Is(err, meta.ErrNotFound) {
		t.Fatalf("authorization code survived offboarding: %v", err)
	}
	if grants, err := store.ListGrants(ctx, alice.ID); err != nil || len(grants) != 0 {
		t.Fatalf("grants after offboarding: %v, %v", grants, err)
	}

	if w := request(http.MethodPut, "/api/v1/admin/users/"+intString(alice.ID)+"/access", `{"disabled":false}`, nil); w.Code != http.StatusOK {
		t.Fatalf("enable API: %d %s", w.Code, w.Body.String())
	}
	u, err := store.UserByID(ctx, alice.ID)
	if err != nil || u.Disabled {
		t.Fatalf("account not enabled: user=%+v err=%v", u, err)
	}
	if got := a.Current(cookieReq); got != nil {
		t.Fatalf("enable resurrected a revoked session: %+v", got)
	}
}

func intString(v int64) string {
	return strconv.FormatInt(v, 10)
}
