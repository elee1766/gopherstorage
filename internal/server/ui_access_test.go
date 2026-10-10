package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
)

func TestAdminUIAccountAccessControl(t *testing.T) {
	ctx := context.Background()
	store, err := meta.Open(ctx, t.TempDir()+"/meta.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cfg := &config.Config{PublicURL: "http://storage.test", Session: config.Session{Secret: strings.Repeat("a", 32), MaxAge: time.Hour}}
	a, err := auth.NewSessionsOnly(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.UpsertUser(ctx, meta.Login{Sub: "admin-sub", Username: "admin", IsAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	target, err := store.UpsertUser(ctx, meta.Login{Sub: "target-sub", Username: "target"})
	if err != nil {
		t.Fatal(err)
	}
	adminCookie, err := a.SessionCookie(&auth.Session{UserID: admin.ID, Username: admin.Username})
	if err != nil {
		t.Fatal(err)
	}
	targetCookie, err := a.SessionCookie(&auth.Session{UserID: target.ID, Username: target.Username})
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := blob.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, store, &storage.Service{Meta: store, Blobs: blobs}, a, &oauth.Server{Auth: a, Store: store})
	h := s.Handler()
	request := func(id int64, disabled bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "http://storage.test/ui/admin/users/"+strconv.FormatInt(id, 10)+"/access", strings.NewReader(url.Values{"disabled": {strconv.FormatBool(disabled)}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("HX-Request", "true")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.AddCookie(adminCookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := request(target.ID, true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `>disabled</span>`) || !strings.Contains(w.Body.String(), `>Enable</button>`) {
		t.Fatalf("disable account through UI: status=%d body=%s", w.Code, w.Body.String())
	}
	cookieReq := httptest.NewRequest(http.MethodGet, "http://storage.test/", nil)
	cookieReq.AddCookie(targetCookie)
	if a.Current(cookieReq) != nil {
		t.Fatal("disabled user's copied session remained valid")
	}
	if w := request(admin.ID, true); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "cannot disable your own") {
		t.Fatalf("self-disable should be rejected: status=%d body=%s", w.Code, w.Body.String())
	}
	if u, err := store.UserByID(ctx, admin.ID); err != nil || u.Disabled {
		t.Fatalf("self-disable changed admin access: user=%+v err=%v", u, err)
	}
	if w := request(target.ID, false); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `>enabled</span>`) || !strings.Contains(w.Body.String(), `>Disable</button>`) {
		t.Fatalf("enable account through UI: status=%d body=%s", w.Code, w.Body.String())
	}
}
