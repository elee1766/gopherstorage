// Package ui renders the account web UI and the OAuth pages with templ.
// Interactions use htmx (server-rendered fragments) and the CSP build of
// Alpine.js for small client state, so pages run under a CSP without
// unsafe-eval or unsafe-inline.
package ui

//go:generate go tool templ generate

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"anime.bike/remotestorage/pkg/rs"
)

//go:embed static
var staticFS embed.FS

var assetVersion = map[string]string{}

func init() {
	entries, _ := fs.ReadDir(staticFS, "static")
	for _, e := range entries {
		b, _ := staticFS.ReadFile("static/" + e.Name())
		h := sha256.Sum256(b)
		assetVersion[e.Name()] = hex.EncodeToString(h[:4])
	}
}

// Asset returns the URL of a static file with a content hash, so it can be
// cached for a long time.
func Asset(name string) string {
	return "/static/" + name + "?v=" + assetVersion[name]
}

// StaticHandler serves /static/ (mount it with the prefix stripped).
func StaticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("v"); v != "" && v == assetVersion[strings.TrimPrefix(r.URL.Path, "/")] {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// PageCSP is the Content-Security-Policy for pages rendered by this package.
const PageCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// SetPageHeaders sets the headers every HTML page from this package needs.
func SetPageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	if h.Get("Content-Security-Policy") == "" {
		h.Set("Content-Security-Policy", PageCSP)
	}
}

// Account is everything the account page shows.
type Account struct {
	Username  string
	Name      string
	Address   string
	UsedBytes int64
	Quota     int64 // 0 = unlimited
	Documents int64
	Admin     bool
	Grants    []Grant
	Shared    []Shared
	Tokens    Tokens
	Users     Users
}

type Grant struct {
	ID       int64
	Client   string
	Origin   string
	Scope    string
	LastUsed time.Time
}

type Shared struct {
	Path        string
	URL         string
	ContentType string
	Size        int64
	Modified    time.Time
}

type Token struct {
	ID       int64
	Name     string
	Created  time.Time
	LastUsed time.Time
	Expires  time.Time
}

// Tokens is the API token section. New is the secret of a token that was
// just created; it is shown once.
type Tokens struct {
	List   []Token
	New    string
	NewFor string
	APIURL string
}

type User struct {
	ID         int64
	Username   string
	Admin      bool
	UsedBytes  int64
	QuotaBytes int64
	LastLogin  time.Time
}

type Users struct {
	List         []User
	DefaultQuota int64
}

// Consent is the OAuth authorization page.
type Consent struct {
	User      string
	Client    string
	Scopes    []Scope
	Hidden    map[string][]string
	CSRF      string
	Insecure  bool
	FullScope bool
}

type Scope struct {
	Module string
	Write  bool
}

// Size formats a byte count with binary units.
func Size(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	f := float64(n)
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if f < 10 {
		return fmt.Sprintf("%.1f %s", f, units[i])
	}
	return fmt.Sprintf("%.0f %s", f, units[i])
}

// MiB formats bytes as a MiB number for the quota input ("" for 0).
func MiB(n int64) string {
	if n == 0 {
		return ""
	}
	s := fmt.Sprintf("%.2f", float64(n)/(1<<20))
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	return s
}

func scopeText(scope string) string {
	if strings.TrimSpace(scope) == "" {
		return "No active credentials"
	}
	var parts []string
	for _, s := range strings.Fields(scope) {
		mod, lvl, _ := strings.Cut(s, ":")
		if mod == "*" {
			mod = "everything"
		}
		if lvl == string(rs.ReadWriteAccess) {
			parts = append(parts, mod+" (read/write)")
		} else {
			parts = append(parts, mod+" (read)")
		}
	}
	return strings.Join(parts, ", ")
}

func iso(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func utc(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func percent(used, quota int64) string {
	if quota <= 0 {
		return "0"
	}
	return fmt.Sprintf("%d", min(100, used*100/quota))
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
