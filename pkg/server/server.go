// Package server wires the remoteStorage handler, OAuth, WebFinger and the
// account web UI together.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/webfinger"

	"github.com/elee1766/gopherstorage/pkg/auth"
	"github.com/elee1766/gopherstorage/pkg/config"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"github.com/elee1766/gopherstorage/pkg/oauth"
	"github.com/elee1766/gopherstorage/pkg/storage"
)

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
	_ = s.store.TouchGrant(r.Context(), ti.GrantID)
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
	if u.Disabled {
		return emptyStorage{}, nil
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
	mux.HandleFunc("POST /auth/logout", s.auth.Logout)
	mux.HandleFunc("POST /auth/backchannel-logout", s.auth.BackchannelLogout)
	s.registerAPI(mux)
	s.registerUI(mux)

	return s.requestBoundary(logRequests(s.protectUI(s.routeStorage(mux))))
}

// routeStorage sends /storage/ and /view/ requests straight to their handlers.
// http.ServeMux would clean paths like "a//b" or "a/./b" and redirect,
// instead of letting the handler reject them. When a separate view host is
// configured, that host serves nothing but /view/.
func (s *Server) routeStorage(mux http.Handler) http.Handler {
	storage := http.StripPrefix(strings.TrimSuffix(StoragePrefix, "/"), s.rs)
	vh := s.cfg.ViewHost()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, ViewPrefix):
			s.handleView(w, r)
		case vh != "" && strings.EqualFold(r.Host, vh):
			http.NotFound(w, r)
		case strings.HasPrefix(r.URL.Path, StoragePrefix):
			storage.ServeHTTP(w, r)
		default:
			mux.ServeHTTP(w, r)
		}
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
	cop.AddInsecureBypassPattern("/auth/backchannel-logout")
	return cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, StoragePrefix) && !strings.HasPrefix(r.URL.Path, ViewPrefix) {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/auth/callback" {
			w.Header().Set("Referrer-Policy", "no-referrer")
		} else if !strings.HasPrefix(r.URL.Path, StoragePrefix) && !strings.HasPrefix(r.URL.Path, ViewPrefix) {
			w.Header().Set("Referrer-Policy", "same-origin")
		}
		next.ServeHTTP(w, r)
	}))
}

func (s *Server) webfinger() http.Handler {
	authz := s.cfg.PublicURL + "/oauth/authorize"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wf := webfinger.NewServer(s.cfg.Host(), webfinger.StorageResolverFunc(func(user string) (*webfinger.UserStorageInfo, error) {
			user = strings.ToLower(user)
			if !auth.ValidUsername(user) {
				return nil, nil
			}
			u, err := s.store.UserByName(r.Context(), user)
			if errors.Is(err, meta.ErrNotFound) {
				return nil, nil
			} else if err != nil {
				return nil, err
			} else if u.Disabled {
				return nil, nil
			}
			return &webfinger.UserStorageInfo{
				StorageRoot:         s.cfg.PublicURL + StoragePrefix + user,
				AuthEndpoint:        &authz,
				TokenEndpoint:       s.cfg.PublicURL + "/oauth/token",
				RangeRequestSupport: "GET",
			}, nil
		}))
		wf.ServeHTTP(w, r)
	})
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
