package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"anime.bike/remotestorage/pkg/rsserver"
	"github.com/elee1766/gopherstorage/pkg/auth"
	"github.com/elee1766/gopherstorage/pkg/blob/filesystem"
	"github.com/elee1766/gopherstorage/pkg/config"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"github.com/elee1766/gopherstorage/pkg/meta/sqlite"
	"github.com/elee1766/gopherstorage/pkg/oauth"
	"github.com/elee1766/gopherstorage/pkg/storage"
)

func TestHandlerHostAndSecurityBoundaries(t *testing.T) {
	cfg := &config.Config{
		PublicURL: "https://storage.test",
		Session:   config.Session{Secret: strings.Repeat("s", 32), MaxAge: time.Hour},
	}
	h, _, _ := newLimitsTestHandler(t, cfg)

	do := func(host, path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
		r.RemoteAddr = "192.0.2.10:12345"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := do("attacker.test", "/healthz"); w.Code != http.StatusMisdirectedRequest || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("unknown Host: status=%d cache=%q", w.Code, w.Header().Get("Cache-Control"))
	}
	if w := do("storage.test", "/healthz"); w.Code != http.StatusOK || w.Header().Get("Strict-Transport-Security") == "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("primary HTTPS health: status=%d headers=%v", w.Code, w.Header())
	}
	if w := do("share.test", "/healthz"); w.Code != http.StatusMisdirectedRequest {
		t.Errorf("secondary host accepted: %d", w.Code)
	}
	if w := do("storage.test", "/auth/callback"); w.Code != http.StatusBadRequest || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("OAuth callback policy: status=%d headers=%v", w.Code, w.Header())
	}
	backchannel := httptest.NewRequest(http.MethodPost, "https://storage.test/auth/backchannel-logout", strings.NewReader("logout_token=invalid"))
	backchannel.RemoteAddr = "192.0.2.10:12345"
	backchannel.Header.Set("Origin", "https://idp.test")
	backchannel.Header.Set("Sec-Fetch-Site", "cross-site")
	backchannel.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postResponse := httptest.NewRecorder()
	h.ServeHTTP(postResponse, backchannel)
	if postResponse.Code == http.StatusForbidden || postResponse.Code == http.StatusNotFound {
		t.Errorf("cross-origin backchannel POST did not reach auth handler: %d", postResponse.Code)
	}
	getResponse := do("storage.test", "/auth/backchannel-logout")
	if getResponse.Code != http.StatusMethodNotAllowed {
		t.Errorf("backchannel logout accepted GET: %d", getResponse.Code)
	}
}

func TestHandlerRateLimitUsesRemoteIPNotForwardedHeader(t *testing.T) {
	cfg := &config.Config{
		PublicURL: "http://storage.test",
		Session:   config.Session{Secret: strings.Repeat("s", 32), MaxAge: time.Hour},
		HTTP: config.HTTP{
			MaxConcurrentRequests: 4,
			RatePerMinute:         60,
			RateBurst:             1,
			MaxRateClients:        4,
			RequestTimeout:        time.Second,
		},
	}
	h, _, _ := newLimitsTestHandler(t, cfg)

	do := func(remote, forwarded string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "http://storage.test/healthz", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", forwarded)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("192.0.2.10:12345", "198.51.100.1"); w.Code != http.StatusOK {
		t.Fatalf("initial request: %d", w.Code)
	}
	if w := do("192.0.2.10:12346", "203.0.113.9"); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Errorf("forwarded header bypassed rate limit: status=%d retry-after=%q", w.Code, w.Header().Get("Retry-After"))
	}
	if w := do("192.0.2.11:12345", "198.51.100.1"); w.Code != http.StatusOK {
		t.Errorf("independent remote IP was not admitted: %d", w.Code)
	}
	if w := do("192.0.2.12:12345", "198.51.100.1"); w.Code != http.StatusOK {
		t.Errorf("third remote IP was not admitted within the key bound: %d", w.Code)
	}
	if w := do("192.0.2.13:12345", "198.51.100.1"); w.Code != http.StatusOK {
		t.Errorf("fourth remote IP was not admitted within the key bound: %d", w.Code)
	}
	if w := do("192.0.2.14:12345", "198.51.100.1"); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Errorf("rate key cap was not enforced: status=%d retry-after=%q", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestHandlerRejectsWhenConcurrentSlotIsHeldBySlowConsumer(t *testing.T) {
	cfg := &config.Config{
		PublicURL: "http://storage.test",
		Session:   config.Session{Secret: strings.Repeat("s", 32), MaxAge: time.Hour},
		HTTP: config.HTTP{
			MaxConcurrentRequests: 1,
			RatePerMinute:         600,
			RateBurst:             10,
			MaxRateClients:        4,
			RequestTimeout:        time.Second,
		},
	}
	h, _, _ := newLimitsTestHandler(t, cfg)

	entered := make(chan struct{})
	release := make(chan struct{})
	w := &writeGate{ResponseRecorder: httptest.NewRecorder(), entered: entered, release: release}
	done := make(chan struct{})
	go func() {
		r := httptest.NewRequest(http.MethodGet, "http://storage.test/healthz", nil)
		r.RemoteAddr = "192.0.2.20:12345"
		h.ServeHTTP(w, r)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("health response did not reach the held writer")
	}

	r := httptest.NewRequest(http.MethodGet, "http://storage.test/healthz", nil)
	r.RemoteAddr = "192.0.2.21:12345"
	rejected := httptest.NewRecorder()
	h.ServeHTTP(rejected, r)
	if rejected.Code != http.StatusTooManyRequests || rejected.Header().Get("Retry-After") != "1" {
		t.Errorf("request with full concurrency budget: status=%d retry-after=%q", rejected.Code, rejected.Header().Get("Retry-After"))
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("held handler did not complete after writer release")
	}
}

func TestDisabledUserIsHiddenFromPublicStorageAndWebFinger(t *testing.T) {
	cfg := &config.Config{
		PublicURL: "http://storage.test",
		Session:   config.Session{Secret: strings.Repeat("s", 32), MaxAge: time.Hour},
	}
	h, store, svc := newLimitsTestHandler(t, cfg)
	ctx := context.Background()
	u, err := store.UpsertUser(ctx, meta.Login{Sub: "subject-alice", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ForUser(u).Put(ctx, "/public/note.txt", strings.NewReader("secret"), 6, "text/plain", rsserver.Condition{}); err != nil {
		t.Fatal(err)
	}
	do := func(target string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "http://storage.test"+target, nil)
		r.RemoteAddr = "192.0.2.30:12345"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("/storage/alice/public/note.txt"); w.Code != http.StatusOK {
		t.Fatalf("public storage fixture was not readable before disable: %d", w.Code)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	r := httptest.NewRequest(http.MethodGet, "http://storage.test/.well-known/webfinger?resource=acct:alice@storage.test", nil).WithContext(canceled)
	r.RemoteAddr = "192.0.2.30:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("canceled WebFinger lookup returned %d, want lookup failure", w.Code)
	}
	if err := store.SetUserDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if w := do("/storage/alice/public/note.txt"); w.Code != http.StatusNotFound {
		t.Errorf("disabled user's public document remained accessible: %d", w.Code)
	}
	if w := do("/.well-known/webfinger?resource=acct:alice@storage.test"); w.Code != http.StatusNotFound {
		t.Errorf("disabled user remained discoverable: %d", w.Code)
	}
}

func newLimitsTestHandler(t *testing.T, cfg *config.Config) (http.Handler, meta.Store, *storage.Service) {
	t.Helper()
	store, err := sqlite.Open(context.Background(), t.TempDir()+"/meta.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.NewSessionsOnly(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	svc := &storage.Service{Meta: store, Blobs: blobs}
	return New(cfg, store, svc, a, &oauth.Server{Auth: a, Store: store}).Handler(), store, svc
}

type writeGate struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
}

func (w *writeGate) Write(p []byte) (int, error) {
	select {
	case w.entered <- struct{}{}:
	default:
	}
	<-w.release
	return w.ResponseRecorder.Write(p)
}
