// Package oauth is the authorization server that remoteStorage apps use
// (spec section 10): the implicit grant and the PKCE code flow. The user
// signs in with OIDC, sees a consent page, and the app gets a bearer token.
package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"anime.bike/remotestorage/pkg/rs"

	"github.com/elee1766/gopherstorage/internal/auth"
	"github.com/elee1766/gopherstorage/internal/meta"
	"github.com/elee1766/gopherstorage/internal/ui"
)

const codeTTL = 5 * time.Minute

type Server struct {
	Auth          *auth.Authenticator
	Store         *meta.Store
	TokenTTL      time.Duration
	AllowImplicit bool
	// CSRFKey signs consent forms.
	CSRFKey []byte
}

// request holds the parameters of an authorization request.
type request struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string

	redirect *url.URL
	origin   string
	scopes   []rs.Scope
}

func (q *request) values() url.Values {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("response_type", q.ResponseType)
	set("client_id", q.ClientID)
	set("redirect_uri", q.RedirectURI)
	set("scope", q.Scope)
	set("state", q.State)
	set("code_challenge", q.CodeChallenge)
	set("code_challenge_method", q.CodeChallengeMethod)
	return v
}

// origin computes the web origin of a URL (scheme://host[:port]).
func origin(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func (q *request) isCode() bool { return q.ResponseType == "code" }

// errorRedirect sends an OAuth error back to the app.
func (q *request) errorRedirect(w http.ResponseWriter, r *http.Request, code, desc string) {
	v := url.Values{"error": {code}}
	if desc != "" {
		v.Set("error_description", desc)
	}
	if q.State != "" {
		v.Set("state", q.State)
	}
	u := *q.redirect
	if q.isCode() {
		qs := u.Query()
		for k, vals := range v {
			qs[k] = vals
		}
		u.RawQuery = qs.Encode()
	} else {
		u.Fragment = v.Encode()
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// parse validates an authorization request. It returns false if the error
// was already written (as a page, never as a redirect to an unchecked URI).
func (s *Server) parse(w http.ResponseWriter, r *http.Request) (*request, bool) {
	f := r.Form
	q := &request{
		ResponseType:        f.Get("response_type"),
		ClientID:            f.Get("client_id"),
		RedirectURI:         f.Get("redirect_uri"),
		Scope:               f.Get("scope"),
		State:               f.Get("state"),
		CodeChallenge:       f.Get("code_challenge"),
		CodeChallengeMethod: f.Get("code_challenge_method"),
	}
	if q.ResponseType == "" {
		q.ResponseType = "token"
	}
	u, err := url.Parse(q.RedirectURI)
	if q.RedirectURI == "" || err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.User != nil ||
		(u.Scheme != "https" && u.Scheme != "http") {
		s.page(w, r, http.StatusBadRequest, "Invalid request", "The app sent a missing or invalid redirect_uri.")
		return nil, false
	}
	// Plain http is only allowed for local development.
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		s.page(w, r, http.StatusBadRequest, "Invalid request", "redirect_uri must use https.")
		return nil, false
	}
	q.redirect = u
	q.origin = origin(u)
	// No client registration: the client is identified by its redirect origin
	// (spec section 10). A client_id that is a URL must match that origin.
	if cu, err := url.Parse(q.ClientID); err == nil && cu.IsAbs() && cu.Host != "" && origin(cu) != q.origin {
		q.errorRedirect(w, r, "invalid_request", "client_id does not match the origin of redirect_uri")
		return nil, false
	}
	switch q.ResponseType {
	case "token":
		if !s.AllowImplicit {
			q.errorRedirect(w, r, "unsupported_response_type", "The implicit flow is disabled.")
			return nil, false
		}
	case "code":
		if q.CodeChallengeMethod != rs.PKCEMethodS256 || !rs.ValidS256Challenge(q.CodeChallenge) {
			q.errorRedirect(w, r, "invalid_request", "PKCE with code_challenge_method=S256 is required")
			return nil, false
		}
	default:
		q.errorRedirect(w, r, "unsupported_response_type", "")
		return nil, false
	}
	scopes, invalid := rs.ParseScopes(q.Scope)
	if len(invalid) > 0 || len(scopes) == 0 {
		q.errorRedirect(w, r, "invalid_scope", "scope must be a list of <module>:r or <module>:rw")
		return nil, false
	}
	q.scopes = scopes
	return q, true
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".localhost")
}

// Authorize serves the authorization endpoint (GET shows consent, POST decides).
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self' http: https:; frame-ancestors 'none'")
	if err := r.ParseForm(); err != nil {
		s.page(w, r, http.StatusBadRequest, "Invalid request", "")
		return
	}
	q, ok := s.parse(w, r)
	if !ok {
		return
	}
	sess := s.Auth.Current(r)
	if sess == nil {
		ret := r.URL.Path + "?" + q.values().Encode()
		http.Redirect(w, r, "/auth/login?return="+url.QueryEscape(ret), http.StatusFound)
		return
	}
	if r.Method != http.MethodPost {
		s.consent(w, r, sess, q)
		return
	}
	if !s.checkCSRF(r.PostFormValue("csrf"), sess.UserID, q) {
		s.page(w, r, http.StatusForbidden, "Request expired", "Reload the app and try again.")
		return
	}
	if r.PostFormValue("decision") != "allow" {
		q.errorRedirect(w, r, "access_denied", "")
		return
	}
	s.grant(w, r, sess, q)
}

func (s *Server) grant(w http.ResponseWriter, r *http.Request, sess *auth.Session, q *request) {
	ctx := r.Context()
	scope := rs.FormatScopes(q.scopes)
	grantID, err := s.Store.UpsertGrant(ctx, sess.UserID, q.origin, q.redirect.Host, scope)
	if err != nil {
		if errors.Is(err, meta.ErrCredentialLimit) {
			q.errorRedirect(w, r, "temporarily_unavailable", "The account has reached its credential limit. Revoke existing app access and try again.")
			return
		}
		slog.Error("grant", "err", err)
		q.errorRedirect(w, r, "server_error", "")
		return
	}
	u := *q.redirect
	if q.isCode() {
		code := randomToken()
		if err := s.Store.SaveAuthCode(ctx, code, meta.AuthCode{
			GrantID: grantID, RedirectURI: q.RedirectURI, Scope: scope, CodeChallenge: q.CodeChallenge,
		}, codeTTL); err != nil {
			if errors.Is(err, meta.ErrCredentialLimit) {
				q.errorRedirect(w, r, "temporarily_unavailable", "The account has reached its credential limit. Revoke existing app access and try again.")
				return
			}
			slog.Error("save code", "err", err)
			q.errorRedirect(w, r, "server_error", "")
			return
		}
		v := u.Query()
		v.Set("code", code)
		if q.State != "" {
			v.Set("state", q.State)
		}
		u.RawQuery = v.Encode()
	} else {
		tok, err := s.issue(ctx, grantID, scope)
		if err != nil {
			if errors.Is(err, meta.ErrCredentialLimit) {
				q.errorRedirect(w, r, "temporarily_unavailable", "The account has reached its credential limit. Revoke existing app access and try again.")
				return
			}
			slog.Error("issue token", "err", err)
			q.errorRedirect(w, r, "server_error", "")
			return
		}
		v := url.Values{"access_token": {tok}, "token_type": {"bearer"}, "scope": {scope}}
		if s.TokenTTL > 0 {
			v.Set("expires_in", itoa(int64(s.TokenTTL.Seconds())))
		}
		if q.State != "" {
			v.Set("state", q.State)
		}
		u.Fragment = v.Encode()
	}
	slog.Info("app authorized", "user", sess.Username, "client", q.origin, "scope", scope, "flow", q.ResponseType)
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) issue(ctx context.Context, grantID int64, scope string) (string, error) {
	tok := randomToken()
	return tok, s.Store.IssueToken(ctx, grantID, tok, scope, s.TokenTTL)
}

// Token is the token endpoint of the PKCE code flow.
func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" {
		w.Header().Set("Access-Control-Allow-Origin", o)
		w.Header().Add("Vary", "Origin")
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") || r.ParseForm() != nil {
		oauthError(w, "invalid_request")
		return
	}
	f := r.PostForm
	if f.Get("grant_type") != "authorization_code" {
		if f.Get("grant_type") == "" {
			oauthError(w, "invalid_request")
		} else {
			oauthError(w, "unsupported_grant_type")
		}
		return
	}
	code, redirectURI, verifier := f.Get("code"), f.Get("redirect_uri"), f.Get("code_verifier")
	if code == "" || redirectURI == "" || verifier == "" {
		oauthError(w, "invalid_request")
		return
	}
	ac, err := s.Store.RedeemAuthCode(r.Context(), code)
	if err != nil || ac.RedirectURI != redirectURI || !rs.VerifyS256(verifier, ac.CodeChallenge) {
		oauthError(w, "invalid_grant")
		return
	}
	// client_id is optional for public clients, but must match if sent.
	if cid := f.Get("client_id"); cid != "" {
		ru, _ := url.Parse(redirectURI)
		cu, err := url.Parse(cid)
		if ru == nil || (err == nil && cu.IsAbs() && origin(cu) != origin(ru)) {
			oauthError(w, "invalid_grant")
			return
		}
	}
	tok, err := s.issue(r.Context(), ac.GrantID, ac.Scope)
	if err != nil {
		if errors.Is(err, meta.ErrCredentialLimit) {
			oauthErrorStatus(w, http.StatusTooManyRequests, "temporarily_unavailable")
			return
		}
		slog.Error("issue token", "err", err)
		oauthError(w, "server_error")
		return
	}
	resp := map[string]any{"access_token": tok, "token_type": "bearer", "scope": ac.Scope}
	if s.TokenTTL > 0 {
		resp["expires_in"] = int64(s.TokenTTL.Seconds())
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

func oauthError(w http.ResponseWriter, code string) {
	oauthErrorStatus(w, http.StatusBadRequest, code)
}

func oauthErrorStatus(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func randomToken() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// sign returns a base64url HMAC-SHA256 over the parts.
func sign(key []byte, parts ...string) string {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write([]byte(p))
		m.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// CSRF tokens bind the consent form to the user and request parameters.
func (s *Server) csrf(userID int64, q *request) string {
	return sign(s.CSRFKey, itoa(userID), q.values().Encode())
}

func (s *Server) checkCSRF(got string, userID int64, q *request) bool {
	want := s.csrf(userID, q)
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) consent(w http.ResponseWriter, r *http.Request, sess *auth.Session, q *request) {
	d := ui.Consent{
		User: sess.Username, Client: q.redirect.Host,
		Hidden: q.values(), CSRF: s.csrf(sess.UserID, q), Insecure: q.redirect.Scheme == "http",
	}
	for _, sc := range q.scopes {
		if sc.Module == "*" {
			d.FullScope = true
		}
		d.Scopes = append(d.Scopes, ui.Scope{Module: sc.Module, Write: sc.Access == rs.ReadWriteAccess})
	}
	ui.SetPageHeaders(w)
	if err := ui.ConsentPage(d).Render(r.Context(), w); err != nil {
		slog.Error("consent page", "err", err)
	}
}

func (s *Server) page(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	ui.SetPageHeaders(w)
	w.WriteHeader(status)
	ui.MessagePage(title, msg).Render(r.Context(), w)
}
