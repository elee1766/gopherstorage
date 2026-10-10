package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elee1766/gopherstorage/internal/auth"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/storage"
)

type headerAuth map[string]*auth.User

func (h headerAuth) Authenticate(r *http.Request) *auth.User   { return h[r.Header.Get("X-Test-User")] }
func (headerAuth) Login(http.ResponseWriter, *http.Request)    {}
func (headerAuth) Callback(http.ResponseWriter, *http.Request) {}
func (headerAuth) Logout(http.ResponseWriter, *http.Request)   {}

func TestAccessRules(t *testing.T) {
	fs, err := storage.NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Mounts: []config.Mount{
		{Name: "shared", Backend: "fs", Path: "shared", Read: []string{"*"}, Write: []string{"group:editors"}},
		{Name: "home", Backend: "fs", Path: "users/{username}", Write: []string{"*"}},
		{Name: "private", Backend: "fs", Path: "private", Read: []string{"user:carol"}},
	}}
	users := headerAuth{
		"admin": {Subject: "1", Username: "admin", Admin: true},
		"ed":    {Subject: "2", Username: "ed", Groups: []string{"editors"}},
		"bob":   {Subject: "3", Username: "bob"},
		"evil":  {Subject: "4", Username: "../bob"},
	}
	s, err := New(cfg, users, map[string]storage.Backend{"fs": fs})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	do := func(user, method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		req.Header.Set("X-Test-User", user)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	cases := []struct {
		user, method, path, body string
		want                     int
		wantBody                 string
	}{
		{"", "GET", "/api/me", "", 401, ""},
		{"ed", "PUT", "/api/files/shared/a.txt", "shared", 201, ""},
		{"bob", "GET", "/api/files/shared/a.txt", "", 200, "shared"},
		{"bob", "PUT", "/api/files/shared/a.txt", "x", 403, ""},
		{"bob", "DELETE", "/api/files/shared/a.txt", "", 403, ""},
		{"bob", "GET", "/api/files/private", "", 404, ""},
		{"admin", "PUT", "/api/files/private/p.txt", "p", 201, ""},
		{"bob", "PUT", "/api/files/home/note.txt", "bob note", 201, ""},
		{"ed", "PUT", "/api/files/home/note.txt", "ed note", 201, ""},
		{"bob", "GET", "/api/files/home/note.txt", "", 200, "bob note"},
		{"ed", "GET", "/api/files/home/note.txt", "", 200, "ed note"},
		{"evil", "GET", "/api/files/home/note.txt", "", 403, ""},
		{"bob", "GET", "/api/files/home/..%2fed/note.txt", "", 400, ""},
		{"bob", "DELETE", "/api/files/home", "", 400, ""},
	}
	for _, c := range cases {
		code, body := do(c.user, c.method, c.path, c.body)
		if code != c.want || (c.wantBody != "" && body != c.wantBody) {
			t.Errorf("%s %s %s: got %d %q, want %d %q", c.user, c.method, c.path, code, body, c.want, c.wantBody)
		}
	}
}
