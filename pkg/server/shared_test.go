package server

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
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

func TestFilesExplorerDownloadsAndUnpublishRemainUserScoped(t *testing.T) {
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
	put(alice, "/notes/note.txt", "private note")
	put(alice, "/notes/a + % # ü.txt", "escaped private")
	put(alice, "/public/photos/album/deep/hello.txt", "public photo")
	put(other, "/public/note.txt", "other")
	put(other, "/notes/note.txt", "other private note")
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
	browser := func(target string, session *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "http://storage.test"+target, nil)
		if session != nil {
			r.AddCookie(session)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := browser("/files", nil); w.Code != http.StatusFound || w.Header().Get("Location") != "/auth/login?return=%2Ffiles" {
		t.Fatalf("files page without session: %d %q", w.Code, w.Header().Get("Location"))
	}
	account := browser("/account", cookie)
	if account.Code != http.StatusOK || !strings.Contains(account.Body.String(), `href="/files"`) || strings.Contains(account.Body.String(), "Shared files") {
		t.Fatalf("account files navigation: %d %s", account.Code, account.Body.String())
	}
	root := browser("/files", cookie)
	if root.Code != http.StatusOK || !strings.Contains(root.Body.String(), ">notes/</a>") || !strings.Contains(root.Body.String(), ">public/</a>") {
		t.Fatalf("files root: %d %s", root.Code, root.Body.String())
	}
	notes := browser("/files?path=%2Fnotes%2F", cookie)
	if notes.Code != http.StatusOK || !strings.Contains(notes.Body.String(), "note.txt") || !strings.Contains(notes.Body.String(), "a + % # ü.txt") || !strings.Contains(notes.Body.String(), `href="/files">↑ Parent folder</a>`) {
		t.Fatalf("nested files page or parent link: %d %s", notes.Code, notes.Body.String())
	}
	var escapedDownload string
	for _, match := range regexp.MustCompile(`href="([^"]*/files/download\?path=[^"]+)"`).FindAllStringSubmatch(notes.Body.String(), -1) {
		link, err := url.Parse(html.UnescapeString(match[1]))
		if err == nil && link.Query().Get("path") == "/notes/a + % # ü.txt" {
			escapedDownload = link.RequestURI()
		}
	}
	if escapedDownload == "" {
		t.Fatalf("escaped filename link did not preserve its path: %s", notes.Body.String())
	}
	escapedFile := browser(escapedDownload, cookie)
	if escapedFile.Code != http.StatusOK || escapedFile.Body.String() != "escaped private" {
		t.Fatalf("escaped private download: %d %q", escapedFile.Code, escapedFile.Body.String())
	}
	privateDownload := browser("/files/download?path="+url.QueryEscape("/notes/note.txt"), cookie)
	if privateDownload.Code != http.StatusOK || privateDownload.Body.String() != "private note" || privateDownload.Header().Get("Content-Disposition") != `attachment; filename=note.txt` || privateDownload.Header().Get("X-Content-Type-Options") != "nosniff" || privateDownload.Header().Get("Content-Security-Policy") != "sandbox" || privateDownload.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("private download: %d %q headers=%v", privateDownload.Code, privateDownload.Body.String(), privateDownload.Header())
	}
	headRequest := httptest.NewRequest(http.MethodHead, "http://storage.test/files/download?path="+url.QueryEscape("/notes/note.txt"), nil)
	headRequest.AddCookie(cookie)
	headResponse := httptest.NewRecorder()
	h.ServeHTTP(headResponse, headRequest)
	if headResponse.Code != http.StatusOK || headResponse.Body.Len() != 0 || headResponse.Header().Get("Content-Length") != strconv.Itoa(len("private note")) {
		t.Fatalf("private download HEAD: %d body=%q headers=%v", headResponse.Code, headResponse.Body.String(), headResponse.Header())
	}
	if w := browser("/files/download?path="+url.QueryEscape("/notes/../private/note.txt"), cookie); w.Code != http.StatusNotFound {
		t.Fatalf("traversal download path: %d", w.Code)
	}
	if w := browser("/files/download?path="+url.QueryEscape("/notes/note.txt"), nil); w.Code != http.StatusFound {
		t.Fatalf("private download without session: %d", w.Code)
	}
	otherCookie, err := a.SessionCookie(&auth.Session{UserID: other.ID, Username: other.Username})
	if err != nil {
		t.Fatal(err)
	}
	otherDownload := browser("/files/download?path="+url.QueryEscape("/notes/note.txt"), otherCookie)
	if otherDownload.Code != http.StatusOK || otherDownload.Body.String() != "other private note" {
		t.Fatalf("download was not scoped to the signed-in user's files: %d %q", otherDownload.Code, otherDownload.Body.String())
	}
	if w := browser("/files/download?path="+url.QueryEscape("/public/note.txt"), cookie); w.Code != http.StatusNotFound {
		t.Fatalf("public file should stay on public storage links: %d", w.Code)
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
	lastFile := do("POST", "/ui/unpublish", "path="+url.QueryEscape("/public/photos/album/deep/hello.txt")+"&folder="+url.QueryEscape("/public/photos/album/deep/"), true)
	if lastFile.Code != http.StatusOK || lastFile.Header().Get("HX-Replace-Url") != "/files?path=%2Fpublic%2F" || !strings.Contains(lastFile.Body.String(), "note.txt") || strings.Contains(lastFile.Body.String(), "hello.txt") {
		t.Fatalf("unpublish last file in nested folder: %d %q %s", lastFile.Code, lastFile.Header().Get("HX-Replace-Url"), lastFile.Body.String())
	}
	if _, _, err := svc.ForUser(alice).Get(ctx, "/public/photos/album/deep/hello.txt"); err == nil {
		t.Fatal("last file remains after nested unpublish")
	}
	removed := httptest.NewRecorder()
	h.ServeHTTP(removed, httptest.NewRequest(http.MethodGet, "http://storage.test/view/alice/api.txt", nil))
	if removed.Code != http.StatusNotFound {
		t.Fatalf("removed view endpoint: %d", removed.Code)
	}

	if w := do("POST", "/ui/unpublish", "path="+url.QueryEscape("/public/note.txt")+"&folder="+url.QueryEscape("/public/"), true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/storage/alice/public/api.txt") || strings.Contains(w.Body.String(), "/storage/alice/public/note.txt") {
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
	if err := store.SetUserDisabled(ctx, alice.ID, true); err != nil {
		t.Fatal(err)
	}
	if w := browser("/files", cookie); w.Code != http.StatusFound {
		t.Fatalf("disabled user's files page: %d", w.Code)
	}
	if w := browser("/files/download?path="+url.QueryEscape("/notes/note.txt"), cookie); w.Code != http.StatusFound {
		t.Fatalf("disabled user's private download: %d", w.Code)
	}
}
