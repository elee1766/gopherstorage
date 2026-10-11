package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestUnpublishIsScopedToOwnedPublicDocuments(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(ctx, t.TempDir()+"/meta.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	blobs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{PublicURL: "http://storage.test", Session: config.Session{Secret: strings.Repeat("s", 32), MaxAge: time.Hour}}
	a, err := auth.NewSessionsOnly(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	svc := &storage.Service{Meta: store, Blobs: blobs}
	s := New(cfg, store, svc, a, &oauth.Server{Auth: a, Store: store})
	h := s.Handler()
	alice, err := store.UpsertUser(ctx, meta.Login{Sub: "alice", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.UpsertUser(ctx, meta.Login{Sub: "other", Username: "other"})
	if err != nil {
		t.Fatal(err)
	}
	put := func(u *meta.User, p, body string) {
		t.Helper()
		if _, err := svc.ForUser(u).Put(ctx, p, strings.NewReader(body), int64(len(body)), "text/plain", rsserver.Condition{}); err != nil {
			t.Fatal(err)
		}
	}
	put(alice, "/public/note.txt", "public")
	put(alice, "/public/api.txt", "api public")
	put(alice, "/public/a + % # ü.txt", "escaped public")
	put(alice, "/private/note.txt", "private")
	put(other, "/public/note.txt", "other")
	apiSecret := "gsk_test"
	if _, err := store.CreateAPIToken(ctx, alice.ID, "unpublish test", apiSecret, 0); err != nil {
		t.Fatal(err)
	}
	cookie, err := a.SessionCookie(&auth.Session{UserID: alice.ID, Username: alice.Username})
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, target, body string, useSession bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://storage.test"+target, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if useSession {
			r.AddCookie(cookie)
			r.Header.Set("HX-Request", "true")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
		} else {
			r.Header.Set("Authorization", "Bearer "+apiSecret)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := do("GET", "/api/v1/shared", "", false)
	var response struct {
		Shared []sharedView `json:"shared"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatalf("shared API: %d %s", w.Code, w.Body.String())
	}
	var escapedURL string
	for _, file := range response.Shared {
		if file.Path == "/public/a + % # ü.txt" {
			escapedURL = file.URL
		}
	}
	if escapedURL != "http://storage.test/storage/alice/public/a%20+%20%25%20%23%20%C3%BC.txt" {
		t.Fatalf("public document URL: %q", escapedURL)
	}
	public := httptest.NewRecorder()
	h.ServeHTTP(public, httptest.NewRequest(http.MethodGet, escapedURL, nil))
	if public.Code != http.StatusOK || public.Body.String() != "escaped public" || public.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("anonymous public link: %d %q headers=%v", public.Code, public.Body.String(), public.Header())
	}
	removed := httptest.NewRecorder()
	h.ServeHTTP(removed, httptest.NewRequest(http.MethodGet, "http://storage.test/view/alice/api.txt", nil))
	if removed.Code != http.StatusNotFound {
		t.Fatalf("removed view endpoint: %d", removed.Code)
	}

	if w := do("POST", "/ui/unpublish", "path="+url.QueryEscape("/public/note.txt"), true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/storage/alice/public/api.txt") || strings.Contains(w.Body.String(), "/storage/alice/public/note.txt") {
		t.Fatalf("UI unpublish: %d %s", w.Code, w.Body.String())
	}
	if _, _, err := svc.ForUser(alice).Get(ctx, "/public/note.txt"); err == nil {
		t.Fatal("public document remains after UI unpublish")
	}
	if _, _, err := svc.ForUser(alice).Get(ctx, "/private/note.txt"); err != nil {
		t.Fatalf("private document was affected: %v", err)
	}
	if _, _, err := svc.ForUser(other).Get(ctx, "/public/note.txt"); err != nil {
		t.Fatalf("another user's public document was affected: %v", err)
	}

	for _, p := range []string{"/private/note.txt", "/public/", "/public/../private/note.txt"} {
		w := do("DELETE", "/api/v1/shared?path="+url.QueryEscape(p), "", false)
		if w.Code != http.StatusBadRequest {
			t.Errorf("unpublish path %q status %d, want 400", p, w.Code)
		}
	}
	w = do("DELETE", "/api/v1/shared?path="+url.QueryEscape("/public/api.txt"), "", false)
	if w.Code != http.StatusNoContent {
		t.Fatalf("API unpublish: %d %s", w.Code, w.Body.String())
	}
	if _, _, err := svc.ForUser(alice).Get(ctx, "/public/api.txt"); err == nil {
		t.Fatal("public document remains after API unpublish")
	}
}
