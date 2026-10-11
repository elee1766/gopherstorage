package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/url"
	"path"
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

// Browser UI. GET /account renders the console; the /ui/ endpoints are htmx
// actions that return the HTML fragment to swap in. They use the session
// cookie and are protected against CSRF by http.CrossOriginProtection
// (Sec-Fetch-Site / Origin) plus the HX-Request header, which a cross-origin
// form cannot send.

func (s *Server) registerUI(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /account", s.handleAccount)
	mux.HandleFunc("GET /files", s.handleFiles)
	mux.HandleFunc("GET /files/download", s.handleFileDownload)
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
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, "gopherstorage\n\nremoteStorage server\n\naccount: %s/account\n", s.cfg.PublicURL)
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := s.auth.Current(r)
	if sess == nil {
		http.Redirect(w, r, "/auth/login?return=%2Faccount", http.StatusFound)
		return
	}
	a, err := s.accountView(r, sess)
	if errors.Is(err, meta.ErrNotFound) {
		http.Redirect(w, r, "/auth/login?return=%2Faccount", http.StatusFound)
		return
	}
	if err != nil {
		slog.Error("account page", "err", err)
		render(w, r, http.StatusInternalServerError, ui.MessagePage("Something went wrong", "The account could not be loaded."))
		return
	}
	render(w, r, http.StatusOK, ui.AccountPage(*a))
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := s.auth.Current(r)
	if sess == nil {
		http.Redirect(w, r, "/auth/login?return=%2Ffiles", http.StatusFound)
		return
	}
	u, err := s.store.UserByID(r.Context(), sess.UserID)
	if errors.Is(err, meta.ErrNotFound) || (err == nil && u.Disabled) {
		http.Redirect(w, r, "/auth/login?return=%2Ffiles", http.StatusFound)
		return
	}
	if err != nil {
		slog.Error("files page user lookup", "err", err)
		render(w, r, http.StatusInternalServerError, ui.MessagePage("Something went wrong", "Your files could not be loaded."))
		return
	}
	folder := r.URL.Query().Get("path")
	if folder == "" {
		folder = "/"
	}
	if !canonicalFolder(folder) {
		http.NotFound(w, r)
		return
	}
	page, err := s.filesView(r, u, folder)
	if err != nil {
		if errors.Is(err, meta.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("files page listing", "user", u.Username, "folder", folder, "err", err)
		render(w, r, http.StatusInternalServerError, ui.MessagePage("Something went wrong", "This folder could not be loaded."))
		return
	}
	render(w, r, http.StatusOK, ui.FilesPage(page))
}

func (s *Server) filesView(r *http.Request, u *meta.User, folder string) (ui.Files, error) {
	limit := s.storage.MaxFolderChildren
	if limit <= 0 {
		limit = 10_000
	}
	node, children, err := s.store.ListFolderLimit(r.Context(), u.ID, folder, limit)
	if err != nil {
		return ui.Files{}, err
	}
	if folder != "/" && (node == nil || !node.IsFolder) {
		return ui.Files{}, meta.ErrNotFound
	}
	page := ui.Files{Username: u.Username, Folder: folder}
	if folder != "/" {
		page.Parent = path.Dir(strings.TrimSuffix(folder, "/"))
		if page.Parent == "." || page.Parent == "" {
			page.Parent = "/"
		} else if page.Parent != "/" {
			page.Parent += "/"
		}
	}
	for _, segment := range strings.Split(strings.Trim(folder, "/"), "/") {
		if segment == "" {
			continue
		}
		if len(page.Breadcrumbs) == 0 {
			folderPath := "/" + segment + "/"
			page.Breadcrumbs = append(page.Breadcrumbs, ui.Breadcrumb{Name: segment, Path: folderPath})
		} else {
			folderPath := strings.TrimSuffix(page.Breadcrumbs[len(page.Breadcrumbs)-1].Path, "/") + "/" + segment + "/"
			page.Breadcrumbs = append(page.Breadcrumbs, ui.Breadcrumb{Name: segment, Path: folderPath})
		}
	}
	for _, child := range children {
		item := ui.File{Path: child.Path, Name: path.Base(strings.TrimSuffix(child.Path, "/")), Folder: child.IsFolder, Size: child.Size, ContentType: child.ContentType, Modified: child.Modified}
		if child.IsFolder {
			item.BrowseURL = "/files?path=" + url.QueryEscape(child.Path)
		} else {
			item.DownloadURL = "/files/download?path=" + url.QueryEscape(child.Path)
			if strings.HasPrefix(child.Path, "/public/") {
				item.PublicURL = s.publicDocumentURL(u.Username, child.Path)
			}
		}
		page.Items = append(page.Items, item)
	}
	return page, nil
}

func canonicalFolder(p string) bool {
	return p == "/" || (strings.HasSuffix(p, "/") && path.Clean(p)+"/" == p && rs.ValidatePath(strings.TrimSuffix(p, "/")) == nil)
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := s.auth.Current(r)
	if sess == nil {
		http.Redirect(w, r, "/auth/login?return=%2Ffiles", http.StatusFound)
		return
	}
	u, err := s.store.UserByID(r.Context(), sess.UserID)
	if err != nil || u.Disabled {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	filePath := r.URL.Query().Get("path")
	if !canonicalUserDocument(filePath) {
		http.NotFound(w, r)
		return
	}
	doc, _, err := s.storage.ForUser(u).Get(r.Context(), filePath)
	if err != nil {
		if errors.Is(err, rs.ErrNotFound) || errors.Is(err, meta.ErrNotFound) {
			http.NotFound(w, r)
		} else {
			slog.Error("private file download", "user", u.Username, "path", filePath, "err", err)
			http.Error(w, "could not download file", http.StatusInternalServerError)
		}
		return
	}
	defer doc.Body.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(filePath)}))
	w.Header().Set("Content-Security-Policy", "sandbox")
	w.Header().Set("Content-Length", strconv.FormatInt(doc.Metadata.Size, 10))
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, doc.Body); err != nil {
		slog.Error("private file download stream", "user", u.Username, "path", filePath, "err", err)
	}
}

func canonicalUserDocument(p string) bool {
	return p != "/" && !strings.HasPrefix(p, "/public/") && !strings.HasSuffix(p, "/") && path.Clean(p) == p && rs.ValidatePath(p) == nil && !rs.IsFolderPath(p)
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
	folder := r.PostFormValue("folder")
	if !canonicalFolder(folder) {
		folder = "/"
	}
	var page ui.Files
	var err error
	for {
		page, err = s.filesView(r, u, folder)
		if !errors.Is(err, meta.ErrNotFound) || folder == "/" {
			break
		}
		folder = path.Dir(strings.TrimSuffix(folder, "/"))
		if folder == "." || folder == "" {
			folder = "/"
		} else if folder != "/" {
			folder += "/"
		}
	}
	if err != nil {
		flash(w, r, http.StatusInternalServerError, "Could not load files.")
		return
	}
	if folder == "/" {
		w.Header().Set("HX-Replace-Url", "/files")
	} else {
		w.Header().Set("HX-Replace-Url", "/files?path="+url.QueryEscape(folder))
	}
	render(w, r, http.StatusOK, ui.FilesExplorer(page))
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
