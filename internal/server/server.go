// Package server wires the remoteStorage handler, OAuth, WebFinger and the
// account web UI together.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/webfinger"

	"github.com/elee1766/gopherstorage/internal/auth"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/meta"
	"github.com/elee1766/gopherstorage/internal/oauth"
	"github.com/elee1766/gopherstorage/internal/storage"
)

//go:embed web
var webFS embed.FS

// StoragePrefix is where user storage roots live: <public_url>/storage/<user>.
const StoragePrefix = "/storage/"

type Server struct {
	cfg     *config.Config
	store   *meta.Store
	storage *storage.Service
	auth    *auth.Authenticator
	oauth   *oauth.Server
	rs      http.Handler
}

func New(cfg *config.Config, store *meta.Store, svc *storage.Service, a *auth.Authenticator, o *oauth.Server) *Server {
	s := &Server{cfg: cfg, store: store, storage: svc, auth: a, oauth: o}
	s.rs = rsserver.NewBuilder().
		WithResourceResolver(resolver{}).
		WithAuthenticator(rsserver.AuthenticatorFunc(s.authenticate)).
		WithAuthorizer(rsserver.NewScopeCheckingAuthorizer()).
		WithStorageProvider(rsserver.StorageProviderFunc(s.storageFor)).
		WithMaxDocumentSize(cfg.Storage.MaxDocumentBytes).
		MustBuild()
	return s
}

// resolver maps /<user>/<path> (after StoragePrefix is stripped) to a resource.
type resolver struct{}

func (resolver) ResolveResource(r *http.Request) (*rsserver.ResourceRef, error) {
	rest := strings.TrimPrefix(r.URL.EscapedPath(), "/")
	user, p, ok := strings.Cut(rest, "/")
	if !ok || !auth.ValidUsername(user) {
		return nil, rsserver.NewHTTPError(http.StatusNotFound, "Not found")
	}
	path, err := rsserver.UnescapePath("/" + p)
	if err != nil {
		return nil, err
	}
	return &rsserver.ResourceRef{RequestedUser: user, Path: path}, nil
}

func (s *Server) authenticate(r *http.Request, token string) (*rsserver.AuthInfo, error) {
	if token == "" {
		return nil, nil
	}
	ti, err := s.store.LookupToken(r.Context(), token)
	if errors.Is(err, meta.ErrNotFound) {
		return nil, rsserver.NewHTTPError(http.StatusUnauthorized, "Invalid or expired token")
	}
	if err != nil {
		return nil, err
	}
	scopes, _ := rs.ParseScopes(ti.Scope)
	go s.store.TouchGrant(context.WithoutCancel(r.Context()), ti.GrantID)
	return &rsserver.AuthInfo{UserID: strconv.FormatInt(ti.UserID, 10), Username: ti.Username, Scopes: scopes}, nil
}

func (s *Server) storageFor(ctx context.Context, _ *rsserver.AuthInfo, req *rsserver.ResourceRequest) (rsserver.StorageBackend, error) {
	u, err := s.store.UserByName(ctx, req.Resource.RequestedUser)
	if errors.Is(err, meta.ErrNotFound) {
		// Unknown users look like empty storage to authorized callers;
		// public reads get 404 from the empty tree.
		return emptyStorage{}, nil
	}
	if err != nil {
		return nil, err
	}
	return s.storage.ForUser(u), nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })

	// remoteStorage (/storage/ is routed in routeStorage)
	mux.Handle("/.well-known/webfinger", s.webfinger())
	mux.HandleFunc("/oauth/authorize", s.oauth.Authorize)
	mux.HandleFunc("/oauth/token", s.oauth.Token)

	// Login and account UI
	mux.HandleFunc("GET /auth/login", s.auth.Login)
	mux.HandleFunc("GET /auth/callback", s.auth.Callback)
	mux.HandleFunc("GET /auth/logout", s.auth.Logout)
	mux.HandleFunc("POST /auth/logout", s.auth.Logout)
	mux.HandleFunc("GET /api/account", s.handleAccount)
	mux.HandleFunc("DELETE /api/grants/{id}", s.handleRevoke)
	mux.HandleFunc("GET /api/admin/users", s.handleAdminUsers)
	mux.HandleFunc("PUT /api/admin/users/{id}/quota", s.handleSetQuota)
	mux.HandleFunc("GET /{$}", s.handleIndex)
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(sub)))

	return logRequests(s.protectUI(s.routeStorage(mux)))
}

// routeStorage sends /storage/ requests straight to the remoteStorage handler.
// http.ServeMux would clean paths like "a//b" or "a/./b" and redirect,
// instead of letting the handler reject them.
func (s *Server) routeStorage(mux http.Handler) http.Handler {
	storage := http.StripPrefix(strings.TrimSuffix(StoragePrefix, "/"), s.rs)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, StoragePrefix) {
			storage.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// protectUI applies cross-origin protection and security headers to
// everything except the remoteStorage API, OAuth and WebFinger, which must be
// usable from other origins.
func (s *Server) protectUI(next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	cop.AddInsecureBypassPattern(StoragePrefix)
	cop.AddInsecureBypassPattern("/oauth/token")
	cop.AddInsecureBypassPattern("/.well-known/webfinger")
	return cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !strings.HasPrefix(r.URL.Path, StoragePrefix) {
			w.Header().Set("Referrer-Policy", "same-origin")
		}
		next.ServeHTTP(w, r)
	}))
}

func (s *Server) webfinger() http.Handler {
	authz := s.cfg.PublicURL + "/oauth/authorize"
	wf := webfinger.NewServer(s.cfg.Host(), webfinger.StorageResolverFunc(func(user string) (*webfinger.UserStorageInfo, error) {
		user = strings.ToLower(user)
		if !auth.ValidUsername(user) {
			return nil, nil
		}
		if _, err := s.store.UserByName(context.Background(), user); errors.Is(err, meta.ErrNotFound) {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
		return &webfinger.UserStorageInfo{
			StorageRoot:         s.cfg.PublicURL + StoragePrefix + user,
			AuthEndpoint:        &authz,
			TokenEndpoint:       s.cfg.PublicURL + "/oauth/token",
			RangeRequestSupport: "GET",
		}, nil
	}))
	return wf
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) *auth.Session {
	sess := s.auth.Current(r)
	if sess == nil {
		jsonError(w, http.StatusUnauthorized, "not signed in")
	}
	return sess
}

type grantView struct {
	ID       int64     `json:"id"`
	Client   string    `json:"client"`
	Origin   string    `json:"origin"`
	Scope    string    `json:"scope"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"`
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	if sess == nil {
		return
	}
	ctx := r.Context()
	u, err := s.store.UserByID(ctx, sess.UserID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "account lookup failed")
		return
	}
	docs, _, err := s.store.Usage(ctx, u.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "usage lookup failed")
		return
	}
	grants, err := s.store.ListGrants(ctx, u.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "grant lookup failed")
		return
	}
	gv := []grantView{}
	for _, g := range grants {
		v := grantView{ID: g.ID, Client: g.ClientName, Origin: g.ClientID, Scope: g.Scope, Created: g.CreatedAt}
		if g.LastUsedAt.Unix() > 0 {
			v.LastUsed = g.LastUsedAt
		}
		gv = append(gv, v)
	}
	quota := u.QuotaBytes
	if quota == 0 {
		quota = s.cfg.Storage.DefaultQuotaBytes
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":     u.Username,
		"name":         sess.Name,
		"address":      u.Username + "@" + s.cfg.Host(),
		"storage_root": s.cfg.PublicURL + StoragePrefix + u.Username,
		"used_bytes":   u.UsedBytes,
		"quota_bytes":  quota,
		"documents":    docs,
		"admin":        sess.Admin,
		"grants":       gv,
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	sess := s.session(w, r)
	if sess == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.store.RevokeGrant(r.Context(), sess.UserID, id); errors.Is(err, meta.ErrNotFound) {
		jsonError(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	slog.Info("grant revoked", "user", sess.Username, "grant", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) *auth.Session {
	sess := s.session(w, r)
	if sess != nil && !sess.Admin {
		jsonError(w, http.StatusForbidden, "admins only")
		return nil
	}
	return sess
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if s.admin(w, r) == nil {
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := []map[string]any{}
	for _, u := range users {
		out = append(out, map[string]any{
			"id": u.ID, "username": u.Username, "email": u.Email,
			"used_bytes": u.UsedBytes, "quota_bytes": u.QuotaBytes, "last_login": u.LastLogin,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "default_quota_bytes": s.cfg.Storage.DefaultQuotaBytes})
}

func (s *Server) handleSetQuota(w http.ResponseWriter, r *http.Request) {
	sess := s.admin(w, r)
	if sess == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var body struct {
		QuotaBytes int64 `json:"quota_bytes"`
	}
	if err != nil || json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body) != nil || body.QuotaBytes < 0 {
		jsonError(w, http.StatusBadRequest, "body must be {\"quota_bytes\": n}")
		return
	}
	if err := s.store.SetQuota(r.Context(), id, body.QuotaBytes); err != nil {
		jsonError(w, http.StatusInternalServerError, "update failed")
		return
	}
	slog.Info("quota set", "admin", sess.Username, "user", id, "bytes", body.QuotaBytes)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	data, _ := webFS.ReadFile("web/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Write(data)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		h.ServeHTTP(sw, r)
		if r.URL.Path == "/healthz" {
			return
		}
		slog.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "dur", time.Since(start).Round(time.Millisecond))
	})
}
