package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"

	"github.com/elee1766/gopherstorage/pkg/auth"
	"github.com/elee1766/gopherstorage/pkg/meta"
	"github.com/elee1766/gopherstorage/pkg/ui"
)

// Browser UI. GET / renders the whole page; the /ui/ endpoints are htmx
// actions that return the HTML fragment to swap in. They use the session
// cookie and are protected against CSRF by http.CrossOriginProtection
// (Sec-Fetch-Site / Origin) plus the HX-Request header, which a cross-origin
// form cannot send.

const (
	sharedOnPage = 50
)

func (s *Server) registerUI(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("DELETE /ui/grants/{id}", s.uiHandler(false, s.uiRevokeGrant))
	mux.HandleFunc("POST /ui/unpublish", s.uiHandler(false, s.uiUnpublish))
	mux.HandleFunc("POST /ui/tokens", s.uiHandler(false, s.uiCreateToken))
	mux.HandleFunc("DELETE /ui/tokens/{id}", s.uiHandler(false, s.uiDeleteToken))
	mux.HandleFunc("PUT /ui/admin/users/{id}/quota", s.uiHandler(true, s.uiSetQuota))
	mux.HandleFunc("PUT /ui/admin/users/{id}/access", s.uiHandler(true, s.uiSetUserAccess))
	mux.Handle("GET /static/", http.StripPrefix("/static", ui.StaticHandler()))
}

func render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	ui.SetPageHeaders(w)
	w.WriteHeader(status)
	if err := c.Render(r.Context(), w); err != nil {
		slog.Error("render", "err", err)
	}
}

// flash shows msg in the page's error banner instead of the request target.
func flash(w http.ResponseWriter, r *http.Request, status int, msg string) {
	w.Header().Set("HX-Retarget", "#flash")
	w.Header().Set("HX-Reswap", "innerHTML")
	render(w, r, status, ui.Flash(msg))
}

type uiFunc func(w http.ResponseWriter, r *http.Request, sess *auth.Session, u *meta.User)

func (s *Server) uiHandler(adminOnly bool, h uiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("HX-Request") != "true" {
			http.Error(w, "this endpoint is for the web UI; use /api/v1 from scripts", http.StatusBadRequest)
			return
		}
		sess := s.auth.Current(r)
		if sess == nil {
			w.Header().Set("HX-Redirect", "/auth/login")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		u, err := s.store.UserByID(r.Context(), sess.UserID)
		if err != nil {
			flash(w, r, http.StatusUnauthorized, "Your account could not be loaded. Sign in again.")
			return
		}
		if adminOnly && !isFreshAdmin(u) {
			flash(w, r, http.StatusForbidden, "Sign in again to verify administrator access.")
			return
		}
		h(w, r, sess, u)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	sess := s.auth.Current(r)
	if sess == nil {
		render(w, r, http.StatusOK, ui.LoginPage())
		return
	}
	a, err := s.accountView(r, sess)
	if errors.Is(err, meta.ErrNotFound) {
		render(w, r, http.StatusOK, ui.LoginPage())
		return
	}
	if err != nil {
		slog.Error("account page", "err", err)
		render(w, r, http.StatusInternalServerError, ui.MessagePage("Something went wrong", "The account could not be loaded."))
		return
	}
	render(w, r, http.StatusOK, ui.AccountPage(*a))
}

func (s *Server) accountView(r *http.Request, sess *auth.Session) (*ui.Account, error) {
	ctx := r.Context()
	u, err := s.store.UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	docs, _, err := s.store.Usage(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	a := &ui.Account{
		Username: u.Username, Name: sess.Name, Address: u.Username + "@" + s.cfg.Host(),
		UsedBytes: u.UsedBytes, Quota: s.effectiveQuota(u), Documents: docs, Admin: isFreshAdmin(u),
	}
	if a.Grants, err = s.uiGrants(r, u.ID); err != nil {
		return nil, err
	}
	shared, err := s.shared(r, u, sharedOnPage)
	if err != nil {
		return nil, err
	}
	for _, f := range shared {
		a.Shared = append(a.Shared, ui.Shared(f))
	}
	if a.Tokens, err = s.uiTokens(r, u.ID); err != nil {
		return nil, err
	}
	if isFreshAdmin(u) {
		if a.Users, err = s.uiUsers(r); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (s *Server) uiGrants(r *http.Request, userID int64) ([]ui.Grant, error) {
	gs, err := s.grants(r, userID)
	var out []ui.Grant
	for _, g := range gs {
		out = append(out, ui.Grant{ID: g.ID, Client: g.Client, Origin: g.Origin, Scope: g.Scope, LastUsed: g.LastUsed})
	}
	return out, err
}

func (s *Server) uiTokens(r *http.Request, userID int64) (ui.Tokens, error) {
	ts, err := s.tokens(r, userID, 0)
	t := ui.Tokens{APIURL: s.cfg.PublicURL + "/api/v1/"}
	for _, k := range ts {
		t.List = append(t.List, ui.Token{ID: k.ID, Name: k.Name, Created: k.Created, LastUsed: k.LastUsed, Expires: k.Expires})
	}
	return t, err
}

func (s *Server) uiUsers(r *http.Request) (ui.Users, error) {
	us, err := s.users(r)
	out := ui.Users{DefaultQuota: s.cfg.Storage.DefaultQuotaBytes}
	for _, u := range us {
		out.List = append(out.List, ui.User{ID: u.ID, Username: u.Username, Admin: u.Admin, UsedBytes: u.UsedBytes, QuotaBytes: u.QuotaBytes, LastLogin: u.LastLogin, Disabled: u.Disabled})
	}
	return out, err
}

func uiPathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		flash(w, r, http.StatusBadRequest, "Invalid id.")
		return 0, false
	}
	return id, true
}

func (s *Server) uiUnpublish(w http.ResponseWriter, r *http.Request, _ *auth.Session, u *meta.User) {
	publicPath, ok := canonicalPublicDocument(r.PostFormValue("path"))
	if !ok {
		flash(w, r, http.StatusBadRequest, "Choose a file under /public/ to unpublish.")
		return
	}
	if _, err := s.storage.ForUser(u).Delete(r.Context(), publicPath, rsserver.Condition{}); err != nil {
		if errors.Is(err, rs.ErrNotFound) {
			flash(w, r, http.StatusNotFound, "The file was not found.")
		} else {
			slog.Error("unpublish", "user", u.Username, "path", publicPath, "err", err)
			flash(w, r, http.StatusInternalServerError, "Could not unpublish the file.")
		}
		return
	}
	slog.Info("shared file unpublished", "user", u.Username, "path", publicPath, "via", "ui")
	shared, err := s.shared(r, u, sharedOnPage)
	if err != nil {
		flash(w, r, http.StatusInternalServerError, "Could not load shared files.")
		return
	}
	files := make([]ui.Shared, 0, len(shared))
	for _, f := range shared {
		files = append(files, ui.Shared(f))
	}
	render(w, r, http.StatusOK, ui.SharedSection(files))
}

func (s *Server) uiRevokeGrant(w http.ResponseWriter, r *http.Request, _ *auth.Session, u *meta.User) {
	id, ok := uiPathID(w, r)
	if !ok {
		return
	}
	err := s.store.RevokeGrant(r.Context(), u.ID, id)
	if err != nil && !errors.Is(err, meta.ErrNotFound) {
		slog.Error("revoke grant", "err", err)
		flash(w, r, http.StatusInternalServerError, "Could not disconnect the app.")
		return
	}
	if err == nil {
		slog.Info("grant revoked", "user", u.Username, "grant", id, "via", "ui")
	}
	grants, err := s.uiGrants(r, u.ID)
	if err != nil {
		flash(w, r, http.StatusInternalServerError, "Could not load apps.")
		return
	}
	render(w, r, http.StatusOK, ui.AppsSection(grants))
}

func (s *Server) uiCreateToken(w http.ResponseWriter, r *http.Request, _ *auth.Session, u *meta.User) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 100 {
		flash(w, r, http.StatusBadRequest, "Token name must be 1 to 100 characters.")
		return
	}
	days, err := strconv.Atoi(r.PostFormValue("expires_in_days"))
	if err != nil || days < 0 || days > 3650 {
		flash(w, r, http.StatusBadRequest, "Invalid expiry.")
		return
	}
	var b [32]byte
	rand.Read(b[:])
	secret := APITokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])
	at, err := s.store.CreateAPIToken(r.Context(), u.ID, name, secret, time.Duration(days)*24*time.Hour)
	if err != nil {
		if errors.Is(err, meta.ErrTokenLimit) {
			flash(w, r, http.StatusConflict, "You have too many tokens. Delete some first.")
			return
		}
		slog.Error("create token", "err", err)
		flash(w, r, http.StatusInternalServerError, "Could not create the token.")
		return
	}
	slog.Info("api token created", "user", u.Username, "token", at.ID, "name", name)
	t, err := s.uiTokens(r, u.ID)
	if err != nil {
		flash(w, r, http.StatusInternalServerError, "Could not load tokens.")
		return
	}
	t.New, t.NewFor = secret, name
	render(w, r, http.StatusOK, ui.TokensSection(t))
}

func (s *Server) uiDeleteToken(w http.ResponseWriter, r *http.Request, _ *auth.Session, u *meta.User) {
	id, ok := uiPathID(w, r)
	if !ok {
		return
	}
	err := s.store.DeleteAPIToken(r.Context(), u.ID, id)
	if err != nil && !errors.Is(err, meta.ErrNotFound) {
		slog.Error("delete token", "err", err)
		flash(w, r, http.StatusInternalServerError, "Could not delete the token.")
		return
	}
	if err == nil {
		slog.Info("api token deleted", "user", u.Username, "token", id, "via", "ui")
	}
	t, err := s.uiTokens(r, u.ID)
	if err != nil {
		flash(w, r, http.StatusInternalServerError, "Could not load tokens.")
		return
	}
	render(w, r, http.StatusOK, ui.TokensSection(t))
}

func (s *Server) uiSetUserAccess(w http.ResponseWriter, r *http.Request, _ *auth.Session, admin *meta.User) {
	id, ok := uiPathID(w, r)
	if !ok {
		return
	}
	disabled, err := strconv.ParseBool(r.PostFormValue("disabled"))
	if err != nil {
		flash(w, r, http.StatusBadRequest, "Choose whether the account should be enabled or disabled.")
		return
	}
	if id == admin.ID && disabled {
		flash(w, r, http.StatusBadRequest, "You cannot disable your own administrator account.")
		return
	}
	if err := s.store.SetUserDisabled(r.Context(), id, disabled); errors.Is(err, meta.ErrNotFound) {
		flash(w, r, http.StatusNotFound, "No such user.")
		return
	} else if err != nil {
		slog.Error("set user access", "admin", admin.Username, "user", id, "disabled", disabled, "err", err)
		flash(w, r, http.StatusInternalServerError, "Could not update account access.")
		return
	}
	target, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		flash(w, r, http.StatusInternalServerError, "Could not load the user.")
		return
	}
	slog.Info("user access updated", "admin", admin.Username, "user", id, "disabled", disabled)
	render(w, r, http.StatusOK, ui.UserRow(ui.User{ID: target.ID, Username: target.Username, Admin: target.IsAdmin,
		UsedBytes: target.UsedBytes, QuotaBytes: target.QuotaBytes, LastLogin: target.LastLogin, Disabled: target.Disabled}, s.cfg.Storage.DefaultQuotaBytes))
}

func (s *Server) uiSetQuota(w http.ResponseWriter, r *http.Request, _ *auth.Session, admin *meta.User) {
	id, ok := uiPathID(w, r)
	if !ok {
		return
	}
	var bytes int64
	if v := strings.TrimSpace(r.PostFormValue("quota_mib")); v != "" {
		mib, err := strconv.ParseFloat(v, 64)
		if err != nil || mib < 0 || math.IsNaN(mib) || mib > float64(math.MaxInt64>>20) {
			flash(w, r, http.StatusBadRequest, "Quota must be a number of MiB, or empty for the server default.")
			return
		}
		bytes = int64(math.Round(mib * (1 << 20)))
	}
	if err := s.setQuota(r, admin, id, bytes); errors.Is(err, meta.ErrNotFound) {
		flash(w, r, http.StatusNotFound, "No such user.")
		return
	} else if err != nil {
		flash(w, r, http.StatusInternalServerError, "Could not set the quota.")
		return
	}
	target, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		flash(w, r, http.StatusInternalServerError, "Could not load the user.")
		return
	}
	render(w, r, http.StatusOK, ui.UserRow(ui.User{ID: target.ID, Username: target.Username, Admin: target.IsAdmin,
		UsedBytes: target.UsedBytes, QuotaBytes: target.QuotaBytes, LastLogin: target.LastLogin, Disabled: target.Disabled}, s.cfg.Storage.DefaultQuotaBytes))
}
