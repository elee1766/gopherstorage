package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"anime.bike/remotestorage/pkg/rsserver"

	"github.com/elee1766/gopherstorage/internal/blob"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/meta"
	"github.com/elee1766/gopherstorage/internal/storage"
)

func TestView(t *testing.T) {
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
	svc := &storage.Service{Meta: store, Blobs: blobs}
	u, err := store.UpsertUser(ctx, "sub-alice", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	put := func(p, ct, body string) {
		if _, err := svc.ForUser(u).Put(ctx, p, strings.NewReader(body), int64(len(body)), ct, rsserver.Condition{}); err != nil {
			t.Fatal(err)
		}
	}
	put("/public/photos/cat.png", "image/png", "\x89PNG fake")
	put("/public/clip.mp4", "application/octet-stream", "0123456789")
	put("/public/page.html", "text/html", "<script>alert(1)</script>")
	put("/public/notes.txt", "text/plain", "hi")
	put("/public/archive.zip", "application/zip", "PK")
	put("/public/a b ü.jpg", "image/jpeg", "jpg")
	put("/private.png", "image/png", "secret")

	cfg := &config.Config{PublicURL: "http://storage.test"}
	s := &Server{cfg: cfg, store: store, storage: svc}

	do := func(method, target string, hdr ...string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		s.routeStorage(http.NotFoundHandler()).ServeHTTP(w, req)
		return w
	}

	cases := []struct {
		target           string
		status           int
		ctype, disp, csp string
	}{
		{"/view/alice/photos/cat.png", 200, "image/png", `inline; filename=cat.png`, "default-src 'none'"},
		// Generic stored type falls back to the extension; video stays inline.
		{"/view/alice/clip.mp4", 200, "video/mp4", `inline; filename=clip.mp4`, "media-src 'self'"},
		// Active content is shown, but sandboxed.
		{"/view/alice/page.html", 200, "text/html", `inline; filename=page.html`, "sandbox"},
		{"/view/alice/notes.txt", 200, "text/plain; charset=utf-8", "inline", ""},
		// Unknown types download.
		{"/view/alice/archive.zip", 200, "application/zip", `attachment; filename=archive.zip`, "sandbox"},
		{"/view/alice/a%20b%20%C3%BC.jpg", 200, "image/jpeg", `inline; filename*=utf-8''a%20b%20%C3%BC.jpg`, ""},
		{"/view/alice/photos/cat.png?download", 200, "image/png", "attachment", ""},
		// Only /public/ is reachable; folders, traversal and unknown users are not.
		{"/view/alice/../private.png", 400, "", "", ""},
		{"/view/alice/%2e%2e/private.png", 400, "", "", ""},
		{"/view/alice/photos/", 404, "", "", ""},
		{"/view/alice/missing.png", 404, "", "", ""},
		{"/view/nobody/cat.png", 404, "", "", ""},
	}
	for _, c := range cases {
		w := do("GET", c.target)
		h := w.Header()
		if got := w.Code; got != c.status {
			t.Errorf("%s: status %d, want %d", c.target, got, c.status)
			continue
		}
		if c.status != 200 {
			continue
		}
		if c.ctype != "" && h.Get("Content-Type") != c.ctype {
			t.Errorf("%s: Content-Type %q, want %q", c.target, h.Get("Content-Type"), c.ctype)
		}
		if !strings.HasPrefix(h.Get("Content-Disposition"), c.disp) {
			t.Errorf("%s: Content-Disposition %q, want prefix %q", c.target, h.Get("Content-Disposition"), c.disp)
		}
		if c.csp != "" && !strings.Contains(h.Get("Content-Security-Policy"), c.csp) {
			t.Errorf("%s: CSP %q lacks %q", c.target, h.Get("Content-Security-Policy"), c.csp)
		}
		for k, want := range map[string]string{
			"X-Content-Type-Options":       "nosniff",
			"Access-Control-Allow-Origin":  "*",
			"Cross-Origin-Resource-Policy": "cross-origin",
			"Accept-Ranges":                "bytes",
		} {
			if h.Get(k) != want {
				t.Errorf("%s: %s %q, want %q", c.target, k, h.Get(k), want)
			}
		}
		if h.Get("ETag") == "" || h.Get("Last-Modified") == "" {
			t.Errorf("%s: missing validators", c.target)
		}
	}

	// Range requests for media seeking.
	w := do("GET", "/view/alice/clip.mp4", "Range", "bytes=2-5")
	if w.Code != 206 || w.Body.String() != "2345" || w.Header().Get("Content-Range") != "bytes 2-5/10" {
		t.Errorf("range: %d %q %q", w.Code, w.Body.String(), w.Header().Get("Content-Range"))
	}
	// Conditional requests.
	etag := do("GET", "/view/alice/clip.mp4").Header().Get("ETag")
	if w := do("GET", "/view/alice/clip.mp4", "If-None-Match", etag); w.Code != 304 {
		t.Errorf("If-None-Match: %d", w.Code)
	}
	if w := do("HEAD", "/view/alice/clip.mp4"); w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "10" {
		t.Errorf("HEAD: %d len %d cl %q", w.Code, w.Body.Len(), w.Header().Get("Content-Length"))
	}
	if w := do("PUT", "/view/alice/clip.mp4"); w.Code != 405 {
		t.Errorf("PUT: %d", w.Code)
	}

	// With a separate view host, /view/ only answers there, and that host
	// serves nothing else.
	s.cfg = &config.Config{PublicURL: "http://storage.test", View: config.View{URL: "http://share.test"}}
	if w := do("GET", "/view/alice/notes.txt"); w.Code != 404 {
		t.Errorf("view on main host with view.url set: %d", w.Code)
	}
	req := httptest.NewRequest("GET", "http://share.test/view/alice/notes.txt", nil)
	rec := httptest.NewRecorder()
	s.routeStorage(http.NotFoundHandler()).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("view on view host: %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "http://share.test/storage/alice/public/notes.txt", nil)
	rec = httptest.NewRecorder()
	s.routeStorage(http.NotFoundHandler()).ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("storage API on view host: %d", rec.Code)
	}
	if got := s.ViewURL("alice", "/public/a b.png"); got != "http://share.test/view/alice/a%20b.png" {
		t.Errorf("ViewURL %q", got)
	}
}
