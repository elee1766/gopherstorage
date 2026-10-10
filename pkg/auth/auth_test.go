package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/elee1766/gopherstorage/pkg/config"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"golang.org/x/oauth2"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOIDCTransportRejectsUnsafeDiscoveredURLs(t *testing.T) {
	called := false
	transport := endpointGuardTransport{
		allowInsecure: false,
		base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unexpected transport call")
		}),
	}
	for _, raw := range []string{
		"http://identity.example/token",
		"https://user:password@identity.example/jwks",
	} {
		req := httptest.NewRequest(http.MethodGet, raw, nil)
		if _, err := transport.RoundTrip(req); err == nil {
			t.Errorf("RoundTrip(%q) succeeded, want rejection", raw)
		}
	}
	if called {
		t.Fatal("unsafe endpoint reached the underlying transport")
	}
}

func TestCallbackBadStateKeepsFlowCookie(t *testing.T) {
	flow, err := newSealer(strings.Repeat("f", 32), "flow")
	if err != nil {
		t.Fatal(err)
	}
	a := &Authenticator{
		flow: flow,
		oauth: oauth2.Config{
			ClientID:    "client",
			RedirectURL: "https://storage.example/auth/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://id.example/authorize"},
		},
	}

	loginReq := httptest.NewRequest("GET", "https://storage.example/auth/login", nil)
	loginRes := httptest.NewRecorder()
	a.Login(loginRes, loginReq)
	if loginRes.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("login Cache-Control = %q", loginRes.Header().Get("Cache-Control"))
	}
	cookies := loginRes.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != flowCookie || cookies[0].Value == "" {
		t.Fatalf("login flow cookie = %v", cookies)
	}

	callbackReq := httptest.NewRequest("GET", "https://storage.example/auth/callback?state=wrong&code=unused", nil)
	callbackReq.AddCookie(cookies[0])
	callbackRes := httptest.NewRecorder()
	a.Callback(callbackRes, callbackReq)
	if callbackRes.Code != 400 {
		t.Fatalf("callback status = %d, want 400", callbackRes.Code)
	}
	if callbackRes.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("callback Cache-Control = %q", callbackRes.Header().Get("Cache-Control"))
	}
	if values := callbackRes.Header().Values("Set-Cookie"); len(values) != 0 {
		t.Fatalf("bad-state callback changed cookies: %v", values)
	}
}

func TestLegacySealedSessionWithoutDatabaseIDFailsClosed(t *testing.T) {
	ctx := context.Background()
	store, err := meta.Open(ctx, t.TempDir()+"/meta.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "legacy-user", Username: "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Session: config.Session{Secret: strings.Repeat("s", 32), MaxAge: time.Hour}}
	a, err := NewSessionsOnly(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := a.session.seal(&Session{UserID: u.ID, Username: u.Username}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://storage.test/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: legacy})
	if got := a.Current(r); got != nil {
		t.Fatalf("legacy cookie without a persisted session was accepted: %+v", got)
	}
}

func TestPersistedSessionExpiryInvalidatesCookie(t *testing.T) {
	ctx := context.Background()
	dbPath := t.TempDir() + "/meta.db"
	store, err := meta.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "expiry-user", Username: "expiry"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Session: config.Session{Secret: strings.Repeat("e", 32), MaxAge: time.Hour}}
	a, err := NewSessionsOnly(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := a.SessionCookie(&Session{UserID: u.ID, Username: u.Username})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://storage.test/", nil)
	r.AddCookie(cookie)
	if a.Current(r) == nil {
		t.Fatal("new persisted session was not accepted")
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET expires_at=? WHERE user_id=?`, time.Now().Add(-time.Minute).Unix(), u.ID); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if a.Current(r) != nil {
		t.Fatal("cookie remained valid after persisted session expiration")
	}
}

func TestLogoutPreservesProviderLogoutWithoutExternalFormRedirect(t *testing.T) {
	a := &Authenticator{
		cfg:       config.OIDC{ClientID: "client"},
		publicURL: "https://storage.example",
		endSess:   "https://id.example/logout?tenant=main",
	}

	noJSReq := httptest.NewRequest("POST", "https://storage.example/auth/logout", nil)
	noJSRes := httptest.NewRecorder()
	a.Logout(noJSRes, noJSReq)
	if noJSRes.Code != 200 || !strings.Contains(noJSRes.Body.String(), `href="https://id.example/logout?`) || !strings.Contains(noJSRes.Body.String(), "client_id=client") || !strings.Contains(noJSRes.Body.String(), "post_logout_redirect_uri=https%3A%2F%2Fstorage.example%2F") {
		t.Fatalf("non-JS logout response: %d %s", noJSRes.Code, noJSRes.Body.String())
	}
	if noJSRes.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("non-JS logout Cache-Control = %q", noJSRes.Header().Get("Cache-Control"))
	}
	if !strings.Contains(noJSRes.Header().Get("Set-Cookie"), "gs_session=") {
		t.Fatal("non-JS logout did not clear the session cookie")
	}
	if !strings.Contains(noJSRes.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatalf("logout page CSP = %q", noJSRes.Header().Get("Content-Security-Policy"))
	}

	hxReq := httptest.NewRequest("POST", "https://storage.example/auth/logout", nil)
	hxReq.Header.Set("HX-Request", "true")
	hxRes := httptest.NewRecorder()
	a.Logout(hxRes, hxReq)
	if hxRes.Code != 200 || hxRes.Header().Get("HX-Redirect") == "" {
		t.Fatalf("htmx logout response: %d, HX-Redirect=%q", hxRes.Code, hxRes.Header().Get("HX-Redirect"))
	}
	if hxRes.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("htmx logout Cache-Control = %q", hxRes.Header().Get("Cache-Control"))
	}
	redirect, err := url.Parse(hxRes.Header().Get("HX-Redirect"))
	if err != nil || redirect.Host != "id.example" || redirect.Query().Get("client_id") != "client" || redirect.Query().Get("post_logout_redirect_uri") != "https://storage.example/" {
		t.Fatalf("provider logout URL = %q, err=%v", hxRes.Header().Get("HX-Redirect"), err)
	}
}
