// Package auth handles OpenID Connect login of users to the web UI.
// remoteStorage apps never see OIDC tokens; they get tokens from the
// server's own OAuth endpoints (package oauth) after the user logs in here.
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
)

const (
	sessionCookie = "gs_session"
	flowCookie    = "gs_flow"
	flowTTL       = 10 * time.Minute
)

// Session is the logged-in user, stored in an encrypted cookie.
type Session struct {
	UserID   int64  `json:"uid"`
	Username string `json:"u"`
	Name     string `json:"n,omitempty"`
	Admin    bool   `json:"a,omitempty"`
}

type Authenticator struct {
	cfg       config.OIDC
	publicURL string
	maxAge    time.Duration
	secure    bool
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	oauth     oauth2.Config
	session   *sealer
	flow      *sealer
	endSess   string
	store     *meta.Store
}

func New(ctx context.Context, cfg *config.Config, store *meta.Store) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	var md struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&md)
	sess, err := newSealer(cfg.Session.Secret, "session")
	if err != nil {
		return nil, err
	}
	flow, err := newSealer(cfg.Session.Secret, "flow")
	if err != nil {
		return nil, err
	}
	return &Authenticator{
		cfg:       cfg.OIDC,
		publicURL: cfg.PublicURL,
		maxAge:    cfg.Session.MaxAge,
		secure:    strings.HasPrefix(cfg.PublicURL, "https://"),
		provider:  provider,
		verifier:  provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.PublicURL + "/auth/callback",
			Scopes:       cfg.OIDC.Scopes,
		},
		session: sess,
		flow:    flow,
		endSess: md.EndSession,
		store:   store,
	}, nil
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
	ctx := r.Context()
	c, err := r.Cookie(flowCookie)
	var fs flowState
	if err != nil || a.flow.open(c.Value, &fs) != nil {
		http.Error(w, "login session expired, try again", http.StatusBadRequest)
		return
	}
	a.setCookie(w, flowCookie, "", -1)
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, "login failed: "+e+" "+q.Get("error_description"), http.StatusUnauthorized)
		return
	}
	if q.Get("state") != fs.State {
		http.Error(w, "state mismatch", http.StatusBadRequest)
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
	v, err := a.session.seal(sess, a.maxAge)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, sessionCookie, v, a.maxAge)
	slog.Info("login", "user", sess.Username)
	http.Redirect(w, r, fs.Return, http.StatusFound)
}

func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) {
	a.setCookie(w, sessionCookie, "", -1)
	if a.endSess == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	u, err := url.Parse(a.endSess)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	q := u.Query()
	q.Set("client_id", a.cfg.ClientID)
	q.Set("post_logout_redirect_uri", a.publicURL+"/")
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
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
		return nil, errors.New("you are not in a group that may use this server")
	}
	u, err := a.store.UpsertUser(ctx, sub, username, claimString(claims, "email"))
	if err != nil {
		return nil, err
	}
	name := claimString(claims, "name")
	if name == "" {
		name = u.Username
	}
	return &Session{UserID: u.ID, Username: u.Username, Name: name, Admin: a.cfg.IsAdmin(groups)}, nil
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
	return &s
}
