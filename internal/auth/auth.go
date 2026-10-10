// Package auth handles OpenID Connect login of users to the web UI.
// remoteStorage apps never see OIDC tokens; they get tokens from the
// server's own OAuth endpoints (package oauth) after the user logs in here.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/meta"
	"github.com/elee1766/gopherstorage/internal/ui"
)

const (
	sessionCookie   = "gs_session"
	flowCookie      = "gs_flow"
	flowTTL         = 10 * time.Minute
	authHTTPTimeout = 30 * time.Second
	logoutEvent     = "http://schemas.openid.net/event/backchannel-logout"
)

// Session is the logged-in user, stored in an encrypted cookie.
type Session struct {
	UserID   int64  `json:"uid"`
	Username string `json:"u"`
	Name     string `json:"n,omitempty"`
	// Admin is a login-time snapshot. Authorize against the current database role.
	Admin     bool   `json:"a,omitempty"`
	SessionID string `json:"j,omitempty"`
}

type Authenticator struct {
	cfg        config.OIDC
	publicURL  string
	maxAge     time.Duration
	secure     bool
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	oauth      oauth2.Config
	session    *sealer
	flow       *sealer
	endSess    string
	store      *meta.Store
	httpClient *http.Client
}

func New(ctx context.Context, cfg *config.Config, store *meta.Store) (*Authenticator, error) {
	if err := validateOIDCEndpoint(cfg.OIDC.Issuer, cfg.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("oidc issuer: %w", err)
	}
	client := &http.Client{
		Transport: endpointGuardTransport{base: http.DefaultTransport, allowInsecure: cfg.AllowInsecureHTTP},
		Timeout:   authHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many OIDC redirects")
			}
			if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("OIDC HTTPS redirect downgrade rejected")
			}
			return validateOIDCEndpoint(req.URL.String(), cfg.AllowInsecureHTTP)
		},
	}
	initCtx, cancel := context.WithTimeout(ctx, authHTTPTimeout)
	defer cancel()
	initCtx = context.WithValue(initCtx, oauth2.HTTPClient, client)
	provider, err := oidc.NewProvider(initCtx, cfg.OIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	var md struct {
		EndSession string `json:"end_session_endpoint"`
		JWKSURI    string `json:"jwks_uri"`
		UserInfo   string `json:"userinfo_endpoint"`
	}
	if err := provider.Claims(&md); err != nil {
		return nil, fmt.Errorf("oidc discovery metadata: %w", err)
	}
	endpoint := provider.Endpoint()
	for name, value := range map[string]string{
		"authorization endpoint": endpoint.AuthURL,
		"token endpoint":         endpoint.TokenURL,
		"JWKS endpoint":          md.JWKSURI,
		"userinfo endpoint":      md.UserInfo,
		"end session endpoint":   md.EndSession,
	} {
		if value == "" && (name == "userinfo endpoint" || name == "end session endpoint") {
			continue
		}
		if err := validateOIDCEndpoint(value, cfg.AllowInsecureHTTP); err != nil {
			return nil, fmt.Errorf("oidc %s: %w", name, err)
		}
	}
	a, err := newSessions(cfg, store)
	if err != nil {
		return nil, err
	}
	a.provider = provider
	a.httpClient = client
	a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID})
	a.oauth = oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  cfg.PublicURL + "/auth/callback",
		Scopes:       cfg.OIDC.Scopes,
	}
	a.endSess = md.EndSession
	return a, nil
}

type endpointGuardTransport struct {
	base          http.RoundTripper
	allowInsecure bool
}

func (t endpointGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("invalid OIDC request URL")
	}
	if err := validateOIDCEndpoint(req.URL.String(), t.allowInsecure); err != nil {
		return nil, fmt.Errorf("OIDC request URL rejected: %w", err)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func validateOIDCEndpoint(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	if u.Scheme == "http" && !allowInsecure && !isLoopbackHost(u.Hostname()) {
		return errors.New("must use HTTPS outside loopback")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	return strings.EqualFold(host, "localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}

// NewSessionsOnly returns an Authenticator that can read and issue session
// cookies but cannot log anyone in. It is for tests.
func NewSessionsOnly(cfg *config.Config, store *meta.Store) (*Authenticator, error) {
	return newSessions(cfg, store)
}

func newSessions(cfg *config.Config, store *meta.Store) (*Authenticator, error) {
	sess, err := newSealer(cfg.Session.Secret, "session")
	if err != nil {
		return nil, err
	}
	flow, err := newSealer(cfg.Session.Secret, "flow")
	if err != nil {
		return nil, err
	}
	return &Authenticator{
		cfg:        cfg.OIDC,
		publicURL:  cfg.PublicURL,
		maxAge:     cfg.Session.MaxAge,
		secure:     strings.HasPrefix(cfg.PublicURL, "https://"),
		session:    sess,
		flow:       flow,
		store:      store,
		httpClient: &http.Client{Timeout: authHTTPTimeout},
	}, nil
}

// SessionCookie returns the cookie for sess, as set after a login.
func (a *Authenticator) SessionCookie(sess *Session) (*http.Cookie, error) {
	return a.issueSessionCookie(context.Background(), sess, "", "", "")
}

func (a *Authenticator) issueSessionCookie(ctx context.Context, sess *Session, issuer, subject, oidcSID string) (*http.Cookie, error) {
	if a.store == nil || sess == nil || sess.UserID == 0 {
		return nil, errors.New("session store and user are required")
	}
	rawID := make([]byte, 32)
	if _, err := rand.Read(rawID); err != nil {
		return nil, err
	}
	sessCopy := *sess
	sessCopy.SessionID = base64.RawURLEncoding.EncodeToString(rawID)
	h := sha256.Sum256([]byte(sessCopy.SessionID))
	if err := a.store.CreateSession(ctx, h[:], sessCopy.UserID, issuer, subject, oidcSID, a.maxAge); err != nil {
		return nil, err
	}
	v, err := a.session.seal(&sessCopy, a.maxAge)
	if err != nil {
		_ = a.store.RevokeSession(context.Background(), h[:])
		return nil, err
	}
	return &http.Cookie{Name: sessionCookie, Value: v}, nil
}

type flowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
}

func (a *Authenticator) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// SafeReturn only allows local absolute paths as post-login redirect targets.
func SafeReturn(r string) string {
	if !strings.HasPrefix(r, "/") || strings.HasPrefix(r, "//") || strings.HasPrefix(r, "/\\") {
		return "/"
	}
	return r
}

func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fs := flowState{
		State:    oauth2.GenerateVerifier(),
		Nonce:    oauth2.GenerateVerifier(),
		Verifier: oauth2.GenerateVerifier(),
		Return:   SafeReturn(r.URL.Query().Get("return")),
	}
	v, err := a.flow.seal(fs, flowTTL)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, flowCookie, v, flowTTL)
	http.Redirect(w, r, a.oauth.AuthCodeURL(fs.State, oidc.Nonce(fs.Nonce), oauth2.S256ChallengeOption(fs.Verifier)), http.StatusFound)
}

func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), authHTTPTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.httpClient)
	c, err := r.Cookie(flowCookie)
	var fs flowState
	if err != nil || a.flow.open(c.Value, &fs) != nil {
		http.Error(w, "login session expired, try again", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	if q.Get("state") != fs.State {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	a.setCookie(w, flowCookie, "", -1)
	if e := q.Get("error"); e != "" {
		http.Error(w, "login failed: "+e+" "+q.Get("error_description"), http.StatusUnauthorized)
		return
	}
	tok, err := a.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(fs.Verifier))
	if err != nil {
		slog.Warn("token exchange failed", "err", err)
		http.Error(w, "token exchange failed", http.StatusUnauthorized)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusUnauthorized)
		return
	}
	idt, err := a.verifier.Verify(ctx, rawID)
	if err != nil || idt.Nonce != fs.Nonce {
		slog.Warn("id token rejected", "err", err)
		http.Error(w, "invalid id token", http.StatusUnauthorized)
		return
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		http.Error(w, "invalid claims", http.StatusUnauthorized)
		return
	}
	// Some providers only return profile and group claims from userinfo.
	if ui, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil && ui.Subject == idt.Subject {
		extra := map[string]any{}
		if ui.Claims(&extra) == nil {
			for k, v := range extra {
				if _, ok := claims[k]; !ok {
					claims[k] = v
				}
			}
		}
	}
	sess, err := a.login(ctx, claims)
	if err != nil {
		slog.Warn("login rejected", "err", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var idClaims map[string]any
	if err := idt.Claims(&idClaims); err != nil {
		http.Error(w, "invalid claims", http.StatusUnauthorized)
		return
	}
	cookie, err := a.issueSessionCookie(ctx, sess, idt.Issuer, idt.Subject, claimString(idClaims, "sid"))
	if err != nil {
		if errors.Is(err, meta.ErrSessionLimit) {
			http.Error(w, "too many active sessions; sign out on another device", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, sessionCookie, cookie.Value, a.maxAge)
	slog.Info("login", "user", sess.Username)
	http.Redirect(w, r, fs.Return, http.StatusFound)
}

func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if c, err := r.Cookie(sessionCookie); err == nil {
		var sess Session
		if a.session.open(c.Value, &sess) == nil && sess.SessionID != "" {
			h := sha256.Sum256([]byte(sess.SessionID))
			if err := a.store.RevokeSession(r.Context(), h[:]); err != nil {
				slog.Warn("session revocation failed", "err", err)
			}
		}
	}
	a.setCookie(w, sessionCookie, "", -1)
	if a.endSess == "" {
		a.logoutRedirect(w, r, "/")
		return
	}
	u, err := url.Parse(a.endSess)
	if err != nil {
		a.logoutRedirect(w, r, "/")
		return
	}
	q := u.Query()
	q.Set("client_id", a.cfg.ClientID)
	q.Set("post_logout_redirect_uri", a.publicURL+"/")
	u.RawQuery = q.Encode()
	if r.Header.Get("HX-Request") == "true" {
		a.logoutRedirect(w, r, u.String())
		return
	}
	ui.SetPageHeaders(w)
	if err := ui.LogoutPage(u.String()).Render(r.Context(), w); err != nil {
		slog.Error("logout page", "err", err)
	}
}

func (a *Authenticator) logoutRedirect(w http.ResponseWriter, r *http.Request, target string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func claimString(claims map[string]any, key string) string {
	s, _ := claims[key].(string)
	return s
}

func claimStrings(claims map[string]any, key string) []string {
	switch v := claims[key].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// usernameRe limits usernames to what is safe in URLs and acct: addresses.
var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidUsername reports whether name can be a storage username.
func ValidUsername(name string) bool {
	return usernameRe.MatchString(name) && name != "." && name != ".."
}

func (a *Authenticator) login(ctx context.Context, claims map[string]any) (*Session, error) {
	sub := claimString(claims, "sub")
	if sub == "" {
		return nil, errors.New("token has no sub claim")
	}
	username := strings.ToLower(claimString(claims, a.cfg.UsernameClaim))
	if a.cfg.UsernameClaim == "email" {
		username, _, _ = strings.Cut(username, "@")
	}
	if !ValidUsername(username) {
		return nil, fmt.Errorf("claim %q = %q is not a usable username (lowercase letters, digits, '.', '_', '-')", a.cfg.UsernameClaim, username)
	}
	groups := claimStrings(claims, a.cfg.GroupsClaim)
	if len(a.cfg.AllowedGroups) > 0 && !slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(a.cfg.AllowedGroups, g) }) {
		if u, err := a.store.UserBySub(ctx, sub); err == nil {
			if err := a.store.RevokeUserCredentials(ctx, u.ID); err != nil {
				slog.Warn("credential revocation after denied login failed", "user", u.Username, "err", err)
			}
		}
		return nil, errors.New("you are not in a group that may use this server")
	}
	admin := a.cfg.IsAdmin(groups)
	u, err := a.store.UpsertUser(ctx, meta.Login{Sub: sub, Username: username, Email: claimString(claims, "email"), IsAdmin: admin})
	if err != nil {
		return nil, err
	}
	name := claimString(claims, "name")
	if name == "" {
		name = u.Username
	}
	return &Session{UserID: u.ID, Username: u.Username, Name: name, Admin: admin}, nil
}

// Current returns the session of the request, or nil.
func (a *Authenticator) Current(r *http.Request) *Session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	var s Session
	if a.session.open(c.Value, &s) != nil {
		return nil
	}
	if s.SessionID == "" || a.store == nil {
		return nil
	}
	h := sha256.Sum256([]byte(s.SessionID))
	valid, err := a.store.ValidSession(r.Context(), h[:], s.UserID)
	if err != nil || !valid {
		return nil
	}
	return &s
}

// BackchannelLogout validates and processes an OpenID Connect logout token.
func (a *Authenticator) BackchannelLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		http.Error(w, "invalid logout request", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid logout request", http.StatusBadRequest)
		return
	}
	raw := r.Form.Get("logout_token")
	if raw == "" || a.verifier == nil {
		http.Error(w, "invalid logout token", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), authHTTPTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.httpClient)
	idt, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		http.Error(w, "invalid logout token", http.StatusUnauthorized)
		return
	}
	var standard struct {
		IssuedAt  int64           `json:"iat"`
		ExpiresAt int64           `json:"exp"`
		JTI       string          `json:"jti"`
		Subject   string          `json:"sub"`
		SID       string          `json:"sid"`
		Nonce     json.RawMessage `json:"nonce"`
	}
	var events map[string]json.RawMessage
	if err := idt.Claims(&standard); err != nil || idt.Claims(&struct {
		Events *map[string]json.RawMessage `json:"events"`
	}{Events: &events}) != nil || standard.Nonce != nil || (standard.Subject == "" && standard.SID == "") || standard.JTI == "" {
		http.Error(w, "invalid logout token claims", http.StatusBadRequest)
		return
	}
	var event map[string]json.RawMessage
	if len(events[logoutEvent]) == 0 || json.Unmarshal(events[logoutEvent], &event) != nil || event == nil {
		http.Error(w, "invalid logout token event", http.StatusBadRequest)
		return
	}
	now := time.Now()
	issued := time.Unix(standard.IssuedAt, 0)
	if standard.IssuedAt == 0 || issued.After(now.Add(60*time.Second)) || now.Sub(issued) > 5*time.Minute || standard.ExpiresAt <= now.Unix() || standard.ExpiresAt <= standard.IssuedAt {
		http.Error(w, "stale logout token", http.StatusUnauthorized)
		return
	}
	replayUntil := time.Unix(standard.ExpiresAt, 0)
	if cap := issued.Add(6 * time.Minute); replayUntil.After(cap) {
		replayUntil = cap
	}
	if err := a.store.RevokeOIDCLogout(r.Context(), idt.Issuer, standard.JTI, standard.Subject, standard.SID, replayUntil); err != nil {
		http.Error(w, "logout token rejected", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusOK)
}
