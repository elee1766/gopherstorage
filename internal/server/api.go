package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"

	"github.com/elee1766/gopherstorage/internal/meta"
)

// APITokenPrefix marks personal API tokens so they are easy to recognise
// in config files and secret scanners.
const APITokenPrefix = "gsk_"

// principal is the caller of an account API request.
type principal struct {
	user    *meta.User
	tokenID int64
}

// caller authenticates "Authorization: Bearer gsk_...". The JSON API never
// accepts the session cookie, so it needs no CSRF protection; the browser UI
// uses its own /ui/ endpoints.
func (s *Server) caller(w http.ResponseWriter, r *http.Request) *principal {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !strings.HasPrefix(parts[1], APITokenPrefix) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="gopherstorage"`)
		jsonError(w, http.StatusUnauthorized, "send an API token: Authorization: Bearer "+APITokenPrefix+"... (create one on the account page)")
		return nil
	}
	tok := parts[1]
	at, u, err := s.store.LookupAPIToken(r.Context(), tok)
	if err != nil {
		if !errors.Is(err, meta.ErrNotFound) {
			slog.Error("api token lookup", "err", err)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="gopherstorage", error="invalid_token"`)
		jsonError(w, http.StatusUnauthorized, "invalid or expired token")
		return nil
	}
	return &principal{user: u, tokenID: at.ID}
}

const adminLoginFreshness = 15 * time.Minute

func isFreshAdmin(u *meta.User) bool {
	if u == nil || !u.IsAdmin || u.LastLogin.IsZero() {
		return false
	}
	age := time.Since(u.LastLogin)
	return age >= 0 && age <= adminLoginFreshness
}

// apiHandler wraps an account API handler with authentication.
func (s *Server) apiHandler(adminOnly bool, h func(http.ResponseWriter, *http.Request, *principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := s.caller(w, r)
		if p == nil {
			return
		}
		if adminOnly && !isFreshAdmin(p.user) {
			jsonError(w, http.StatusForbidden, "sign in again to verify administrator access")
			return
		}
		h(w, r, p)
	}
}

func (s *Server) registerAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/account", s.apiHandler(false, s.apiAccount))
	mux.HandleFunc("GET /api/v1/grants", s.apiHandler(false, s.apiGrants))
	mux.HandleFunc("DELETE /api/v1/grants/{id}", s.apiHandler(false, s.apiRevokeGrant))
	mux.HandleFunc("GET /api/v1/shared", s.apiHandler(false, s.apiShared))
	mux.HandleFunc("DELETE /api/v1/shared", s.apiHandler(false, s.apiUnpublish))
	mux.HandleFunc("GET /api/v1/tokens", s.apiHandler(false, s.apiTokens))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.apiHandler(false, s.apiDeleteToken))
	mux.HandleFunc("GET /api/v1/admin/users", s.apiHandler(true, s.apiAdminUsers))
	mux.HandleFunc("PUT /api/v1/admin/users/{id}/quota", s.apiHandler(true, s.apiSetQuota))
	registerLifecycleAPI(mux, s)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { jsonError(w, http.StatusNotFound, "no such endpoint") })
}

// effectiveQuota returns the user's quota, or the server default when unset.
func (s *Server) effectiveQuota(u *meta.User) int64 {
	if u.QuotaBytes != 0 {
		return u.QuotaBytes
	}
	return s.cfg.Storage.DefaultQuotaBytes
}

func (s *Server) apiAccount(w http.ResponseWriter, r *http.Request, p *principal) {
	u := p.user
	docs, _, err := s.store.Usage(r.Context(), u.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "usage lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":     u.Username,
		"address":      u.Username + "@" + s.cfg.Host(),
		"storage_root": s.cfg.PublicURL + StoragePrefix + u.Username,
		"used_bytes":   u.UsedBytes,
		"quota_bytes":  s.effectiveQuota(u),
		"documents":    docs,
		"admin":        isFreshAdmin(u),
	})
}

type grantView struct {
	ID       int64     `json:"id"`
	Client   string    `json:"client"`
	Origin   string    `json:"origin"`
	Scope    string    `json:"scope"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"`
}

func (s *Server) grants(r *http.Request, userID int64) ([]grantView, error) {
	grants, err := s.store.ListGrants(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	out := []grantView{}
	for _, g := range grants {
		v := grantView{ID: g.ID, Client: g.ClientName, Origin: g.ClientID, Scope: g.Scope, Created: g.CreatedAt}
		if g.LastUsedAt.Unix() > 0 {
			v.LastUsed = g.LastUsedAt
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) apiGrants(w http.ResponseWriter, r *http.Request, p *principal) {
	out, err := s.grants(r, p.user.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "grant lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": out})
}

func (s *Server) apiRevokeGrant(w http.ResponseWriter, r *http.Request, p *principal) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.RevokeGrant(r.Context(), p.user.ID, id); errors.Is(err, meta.ErrNotFound) {
		jsonError(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	slog.Info("grant revoked", "user", p.user.Username, "grant", id, "via", "api")
	w.WriteHeader(http.StatusNoContent)
}

type sharedView struct {
	Path        string    `json:"path"`
	URL         string    `json:"url"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	Modified    time.Time `json:"modified"`
}

func (s *Server) shared(r *http.Request, u *meta.User, limit int) ([]sharedView, error) {
	pub, err := s.store.ListPublic(r.Context(), u.ID, limit)
	if err != nil {
		return nil, err
	}
	out := []sharedView{}
	for _, n := range pub {
		ct, _ := viewType(n.ContentType, rs.BaseName(n.Path))
		out = append(out, sharedView{Path: n.Path, URL: s.ViewURL(u.Username, n.Path), ContentType: ct, Size: n.Size, Modified: n.Modified})
	}
	return out, nil
}

func (s *Server) apiShared(w http.ResponseWriter, r *http.Request, p *principal) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			jsonError(w, http.StatusBadRequest, "limit must be 1-1000")
			return
		}
		limit = n
	}
	out, err := s.shared(r, p.user, limit)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "shared lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shared": out})
}

func (s *Server) apiUnpublish(w http.ResponseWriter, r *http.Request, p *principal) {
	publicPath, ok := canonicalPublicDocument(r.URL.Query().Get("path"))
	if !ok {
		jsonError(w, http.StatusBadRequest, "path must identify a document under /public/")
		return
	}
	if _, err := s.storage.ForUser(p.user).Delete(r.Context(), publicPath, rsserver.Condition{}); err != nil {
		if errors.Is(err, rs.ErrNotFound) {
			jsonError(w, http.StatusNotFound, "not found")
		} else {
			slog.Error("unpublish", "user", p.user.Username, "path", publicPath, "err", err)
			jsonError(w, http.StatusInternalServerError, "unpublish failed")
		}
		return
	}
	slog.Info("shared file unpublished", "user", p.user.Username, "path", publicPath, "via", "api")
	w.WriteHeader(http.StatusNoContent)
}

func canonicalPublicDocument(p string) (string, bool) {
	if !strings.HasPrefix(p, "/public/") || strings.HasSuffix(p, "/") || path.Clean(p) != p || rs.ValidatePath(p) != nil || rs.IsFolderPath(p) {
		return "", false
	}
	return p, true
}

type tokenView struct {
	ID       int64     `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"`
	Expires  time.Time `json:"expires,omitzero"`
	Current  bool      `json:"current,omitempty"`
}

func (s *Server) tokens(r *http.Request, userID, current int64) ([]tokenView, error) {
	toks, err := s.store.ListAPITokens(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	out := []tokenView{}
	for _, t := range toks {
		v := tokenView{ID: t.ID, Name: t.Name, Created: t.CreatedAt, Expires: t.ExpiresAt, Current: t.ID == current}
		if t.LastUsedAt.Unix() > 0 {
			v.LastUsed = t.LastUsedAt
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) apiTokens(w http.ResponseWriter, r *http.Request, p *principal) {
	out, err := s.tokens(r, p.user.ID, p.tokenID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "token lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (s *Server) apiDeleteToken(w http.ResponseWriter, r *http.Request, p *principal) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteAPIToken(r.Context(), p.user.ID, id); errors.Is(err, meta.ErrNotFound) {
		jsonError(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	slog.Info("api token deleted", "user", p.user.Username, "token", id, "via", "api")
	w.WriteHeader(http.StatusNoContent)
}

type userView struct {
	ID         int64     `json:"id"`
	Username   string    `json:"username"`
	Email      string    `json:"email,omitempty"`
	Admin      bool      `json:"admin"`
	UsedBytes  int64     `json:"used_bytes"`
	QuotaBytes int64     `json:"quota_bytes"`
	LastLogin  time.Time `json:"last_login"`
	Disabled   bool      `json:"disabled"`
}

func (s *Server) users(r *http.Request) ([]userView, error) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		return nil, err
	}
	out := []userView{}
	for _, u := range users {
		out = append(out, userView{ID: u.ID, Username: u.Username, Email: u.Email, Admin: u.IsAdmin,
			UsedBytes: u.UsedBytes, QuotaBytes: u.QuotaBytes, LastLogin: u.LastLogin, Disabled: u.Disabled})
	}
	return out, nil
}

func (s *Server) apiAdminUsers(w http.ResponseWriter, r *http.Request, _ *principal) {
	out, err := s.users(r)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out, "default_quota_bytes": s.cfg.Storage.DefaultQuotaBytes})
}

func (s *Server) apiSetQuota(w http.ResponseWriter, r *http.Request, p *principal) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		QuotaBytes *int64 `json:"quota_bytes"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body) != nil || body.QuotaBytes == nil || *body.QuotaBytes < 0 {
		jsonError(w, http.StatusBadRequest, `body must be {"quota_bytes": n}, 0 for the server default`)
		return
	}
	if err := s.setQuota(r, p.user, id, *body.QuotaBytes); errors.Is(err, meta.ErrNotFound) {
		jsonError(w, http.StatusNotFound, "no such user")
		return
	} else if err != nil {
		jsonError(w, http.StatusInternalServerError, "update failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setQuota(r *http.Request, admin *meta.User, id, bytes int64) error {
	if _, err := s.store.UserByID(r.Context(), id); err != nil {
		return err
	}
	if err := s.store.SetQuota(r.Context(), id, bytes); err != nil {
		return err
	}
	slog.Info("quota set", "admin", admin.Username, "user", id, "bytes", bytes)
	return nil
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}
