package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"anime.bike/remotestorage/pkg/rsserver"

	"github.com/elee1766/gopherstorage/internal/auth"
	"github.com/elee1766/gopherstorage/internal/blob"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/meta"
	"github.com/elee1766/gopherstorage/internal/oauth"
	"github.com/elee1766/gopherstorage/internal/storage"
)

func TestUnpublishIsScopedToOwnedPublicDocuments(t *testing.T) {
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

	if w := do("POST", "/ui/unpublish", "path="+url.QueryEscape("/public/note.txt"), true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "api.txt") || strings.Contains(w.Body.String(), "/view/alice/note.txt") {
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
	w := do("DELETE", "/api/v1/shared?path="+url.QueryEscape("/public/api.txt"), "", false)
	if w.Code != http.StatusNoContent {
		t.Fatalf("API unpublish: %d %s", w.Code, w.Body.String())
	}
	if _, _, err := svc.ForUser(alice).Get(ctx, "/public/api.txt"); err == nil {
		t.Fatal("public document remains after API unpublish")
	}
}
