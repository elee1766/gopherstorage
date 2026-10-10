package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elee1766/gopherstorage/internal/auth"
	"github.com/elee1766/gopherstorage/internal/blob"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/meta"
	"github.com/elee1766/gopherstorage/internal/oauth"
	"github.com/elee1766/gopherstorage/internal/storage"
	"github.com/elee1766/gopherstorage/internal/ui"
)

// TestAccountUIAndAPI drives the full handler: the htmx UI with a session
// cookie and the JSON API with personal tokens.
func TestAccountUIAndAPI(t *testing.T) {
	ctx := context.Background()
	store, err := meta.Open(ctx, t.TempDir()+"/meta.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	blobs, err := blob.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{PublicURL: "http://storage.test", Session: config.Session{Secret: strings.Repeat("s", 32), MaxAge: time.Hour}}
	cfg.Storage.DefaultQuotaBytes = 1 << 30
	a, err := auth.NewSessionsOnly(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	svc := &storage.Service{Meta: store, Blobs: blobs}
	s := New(cfg, store, svc, a, &oauth.Server{Auth: a, Store: store, CSRFKey: []byte("k")})
	h := s.Handler()

	alice, _ := store.UpsertUser(ctx, meta.Login{Sub: "a", Username: "alice"})
	admin, _ := store.UpsertUser(ctx, meta.Login{Sub: "b", Username: "root", IsAdmin: true})
	grantID, err := store.UpsertGrant(ctx, alice.ID, "https://app.example", "app.example", "notes:rw")
	if err != nil {
		t.Fatal(err)
	}
	cookie := func(u *meta.User) *http.Cookie {
		c, err := a.SessionCookie(&auth.Session{UserID: u.ID, Username: u.Username, Name: u.Username, Admin: u.IsAdmin})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	aliceC, adminC := cookie(alice), cookie(admin)

	type req struct {
		method, path, body string
		hdr                []string
		c                  *http.Cookie
	}
	do := func(q req) *httptest.ResponseRecorder {
		r := httptest.NewRequest(q.method, "http://storage.test"+q.path, strings.NewReader(q.body))
		if q.body != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for i := 0; i+1 < len(q.hdr); i += 2 {
			r.Header.Set(q.hdr[i], q.hdr[i+1])
		}
		if q.c != nil {
			r.AddCookie(q.c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	hx := []string{"HX-Request", "true", "Sec-Fetch-Site", "same-origin"}

	// Signed out: login page. Signed in: account page with strict CSP.
	if w := do(req{method: "GET", path: "/"}); w.Code != 200 || !strings.Contains(w.Body.String(), `href="/auth/login"`) {
		t.Fatalf("login page: %d", w.Code)
	}
	w := do(req{method: "GET", path: "/", c: aliceC})
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "alice@storage.test") || !strings.Contains(body, "app.example") {
		t.Fatalf("account page: %d\n%s", w.Code, body)
	}
	if csp := w.Header().Get("Content-Security-Policy"); csp != ui.PageCSP || strings.Contains(csp, "unsafe") {
		t.Errorf("account CSP %q", csp)
	}
	if strings.Contains(body, `id="users"`) {
		t.Error("non-admin sees the users section")
	}
	if !strings.Contains(do(req{method: "GET", path: "/", c: adminC}).Body.String(), `id="users"`) {
		t.Error("admin does not see the users section")
	}
	// Every asset the page references is served.
	for _, m := range regexp.MustCompile(`(?:src|href)="(/static/[^"]+)"`).FindAllStringSubmatch(body, -1) {
		p := strings.ReplaceAll(m[1], "&amp;", "&")
		if w := do(req{method: "GET", path: p}); w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
			t.Errorf("asset %s: %d %q", p, w.Code, w.Header().Get("Cache-Control"))
		}
	}

	// UI actions need the session, htmx and a same-origin request.
	create := req{method: "POST", path: "/ui/tokens", body: "name=laptop&expires_in_days=30", hdr: hx, c: aliceC}
	if w := do(req{method: "POST", path: "/ui/tokens", body: create.body, c: aliceC, hdr: []string{"Sec-Fetch-Site", "same-origin"}}); w.Code != 400 {
		t.Errorf("UI action without HX-Request: %d", w.Code)
	}
	if w := do(req{method: "POST", path: "/ui/tokens", body: create.body, c: aliceC, hdr: []string{"HX-Request", "true", "Sec-Fetch-Site", "cross-site"}}); w.Code != 403 {
		t.Errorf("cross-site UI action: %d", w.Code)
	}
	if w := do(req{method: "POST", path: "/ui/tokens", body: create.body, hdr: hx}); w.Code != 401 || w.Header().Get("HX-Redirect") != "/auth/login" {
		t.Errorf("signed-out UI action: %d %q", w.Code, w.Header().Get("HX-Redirect"))
	}
	if w := do(req{method: "POST", path: "/ui/tokens", body: "name=&expires_in_days=30", hdr: hx, c: aliceC}); w.Code != 400 || w.Header().Get("HX-Retarget") != "#flash" {
		t.Errorf("invalid token name: %d %q", w.Code, w.Header().Get("HX-Retarget"))
	}

	// Create a token in the UI; the secret is shown once.
	w = do(create)
	tok := regexp.MustCompile(`gsk_[A-Za-z0-9_-]{43}`).FindString(w.Body.String())
	if w.Code != 200 || tok == "" || !strings.HasPrefix(w.Body.String(), `<section id="tokens">`) {
		t.Fatalf("create token: %d\n%s", w.Code, w.Body.String())
	}
	if strings.Contains(do(req{method: "GET", path: "/", c: aliceC}).Body.String(), tok) {
		t.Error("token secret shown again on reload")
	}

	// JSON API with the token.
	api := func(method, path, body, token string) (*httptest.ResponseRecorder, map[string]any) {
		r := httptest.NewRequest(method, "http://storage.test"+path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var m map[string]any
		json.Unmarshal(w.Body.Bytes(), &m)
		return w, m
	}
	if w, m := api("GET", "/api/v1/account", "", tok); w.Code != 200 || m["address"] != "alice@storage.test" || m["quota_bytes"] != float64(1<<30) {
		t.Errorf("account: %d %v", w.Code, m)
	}
	if w, m := api("GET", "/api/v1/tokens", "", tok); w.Code != 200 || len(m["tokens"].([]any)) != 1 || m["tokens"].([]any)[0].(map[string]any)["current"] != true {
		t.Errorf("tokens: %d %v", w.Code, m)
	}
	if w, m := api("GET", "/api/v1/grants", "", tok); w.Code != 200 || len(m["grants"].([]any)) != 1 {
		t.Errorf("grants: %d %v", w.Code, m)
	}
	// The API ignores cookies, rejects other bearer tokens, and has no
	// endpoint to mint tokens.
	r := httptest.NewRequest("GET", "http://storage.test/api/v1/account", nil)
	r.AddCookie(aliceC)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Errorf("API with session cookie: %d", rec.Code)
	}
	for _, bad := range []string{"", "gsk_nope", "some-app-token"} {
		if w, _ := api("GET", "/api/v1/account", "", bad); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("token %q: %d", bad, w.Code)
		}
	}
	if w, _ := api("POST", "/api/v1/tokens", `{"name":"x"}`, tok); w.Code < 400 {
		t.Errorf("token minting via API: %d", w.Code)
	}
	if w, _ := api("GET", "/api/v1/admin/users", "", tok); w.Code != 403 {
		t.Errorf("admin API as user: %d", w.Code)
	}
	if w, _ := api("GET", "/api/v1/nope", "", tok); w.Code != 404 {
		t.Errorf("unknown endpoint: %d", w.Code)
	}

	// Admin token from the admin's UI; set a quota both ways.
	w = do(req{method: "POST", path: "/ui/tokens", body: "name=ops&expires_in_days=0", hdr: hx, c: adminC})
	adminTok := regexp.MustCompile(`gsk_[A-Za-z0-9_-]{43}`).FindString(w.Body.String())
	if w, m := api("GET", "/api/v1/admin/users", "", adminTok); w.Code != 200 || len(m["users"].([]any)) != 2 {
		t.Errorf("admin users: %d %v", w.Code, m)
	}
	if w, _ := api("PUT", "/api/v1/admin/users/"+itoa(alice.ID)+"/quota", `{"quota_bytes":5242880}`, adminTok); w.Code != 204 {
		t.Errorf("API set quota: %d", w.Code)
	}
	if w, _ := api("PUT", "/api/v1/admin/users/9999/quota", `{"quota_bytes":1}`, adminTok); w.Code != 404 {
		t.Errorf("API quota unknown user: %d", w.Code)
	}
	if w := do(req{method: "PUT", path: "/ui/admin/users/" + itoa(alice.ID) + "/quota", body: "quota_mib=2", hdr: hx, c: aliceC}); w.Code != 403 {
		t.Errorf("UI quota as non-admin: %d", w.Code)
	}
	w = do(req{method: "PUT", path: "/ui/admin/users/" + itoa(alice.ID) + "/quota", body: "quota_mib=2.5", hdr: hx, c: adminC})
	if u, _ := store.UserByID(ctx, alice.ID); w.Code != 200 || u.QuotaBytes != 2.5*(1<<20) || !strings.Contains(w.Body.String(), "2.5 MiB") {
		t.Errorf("UI set quota: %d %d\n%s", w.Code, u.QuotaBytes, w.Body.String())
	}
	if w := do(req{method: "PUT", path: "/ui/admin/users/" + itoa(alice.ID) + "/quota", body: "quota_mib=lots", hdr: hx, c: adminC}); w.Code != 400 {
		t.Errorf("UI bad quota: %d", w.Code)
	}

	// Revoke the app in the UI, then delete alice's token with the token
	// itself; afterwards it no longer works. Nobody can touch others' rows.
	if w := do(req{method: "DELETE", path: "/ui/grants/" + itoa(grantID), hdr: hx, c: adminC}); w.Code != 200 {
		t.Errorf("revoke other user's grant: %d", w.Code)
	}
	if gs, _ := store.ListGrants(ctx, alice.ID); len(gs) != 1 {
		t.Error("admin UI revoked another user's grant")
	}
	w = do(req{method: "DELETE", path: "/ui/grants/" + itoa(grantID), hdr: hx, c: aliceC})
	if gs, _ := store.ListGrants(ctx, alice.ID); w.Code != 200 || len(gs) != 0 || !strings.Contains(w.Body.String(), "No apps connected") {
		t.Errorf("revoke grant: %d %d", w.Code, len(gs))
	}
	_, m := api("GET", "/api/v1/tokens", "", tok)
	id := int64(m["tokens"].([]any)[0].(map[string]any)["id"].(float64))
	if w, _ := api("DELETE", "/api/v1/tokens/"+itoa(id), "", adminTok); w.Code != 404 {
		t.Errorf("delete other user's token: %d", w.Code)
	}
	if w, _ := api("DELETE", "/api/v1/tokens/"+itoa(id), "", tok); w.Code != 204 {
		t.Errorf("delete own token: %d", w.Code)
	}
	if w, _ := api("GET", "/api/v1/account", "", tok); w.Code != 401 {
		t.Errorf("deleted token still works: %d", w.Code)
	}

	// Expired tokens stop working.
	if _, err := store.CreateAPIToken(ctx, alice.ID, "old", "gsk_expired", time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if w, _ := api("GET", "/api/v1/account", "", "gsk_expired"); w.Code != 401 {
		t.Errorf("expired token: %d", w.Code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
