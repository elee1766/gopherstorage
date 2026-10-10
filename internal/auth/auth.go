// Package auth handles OpenID Connect login and request authentication.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/elee1766/gopherstorage/internal/config"
)

const (
	sessionCookie = "gs_session"
	flowCookie    = "gs_flow"
	flowTTL       = 10 * time.Minute
)

type User struct {
	Subject  string   `json:"sub"`
	Username string   `json:"username"`
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	Groups   []string `json:"groups"`
	Admin    bool     `json:"admin"`
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

	cacheMu sync.Mutex
	cache   map[[32]byte]cachedUser
}

type cachedUser struct {
	user *User
	exp  time.Time
}

func New(ctx context.Context, cfg *config.Config) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&meta)
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
		endSess: meta.EndSession,
		cache:   map[[32]byte]cachedUser{},
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

// safeReturn only allows local absolute paths as post-login redirect targets.
func safeReturn(r string) string {
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
		Return:   safeReturn(r.URL.Query().Get("return")),
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
	u, err := a.userFromClaims(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	v, err := a.session.seal(u, a.maxAge)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, sessionCookie, v, a.maxAge)
	slog.Info("login", "user", u.Username, "sub", u.Subject)
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

func (a *Authenticator) userFromClaims(claims map[string]any) (*User, error) {
	u := &User{
		Subject:  claimString(claims, "sub"),
		Username: claimString(claims, a.cfg.UsernameClaim),
		Email:    claimString(claims, "email"),
		Name:     claimString(claims, "name"),
		Groups:   claimStrings(claims, a.cfg.GroupsClaim),
	}
	if u.Subject == "" {
		return nil, errors.New("token has no sub claim")
	}
	if u.Username == "" {
		return nil, fmt.Errorf("token has no %q claim", a.cfg.UsernameClaim)
	}
	if u.Groups == nil {
		u.Groups = []string{}
	}
	if len(a.cfg.AllowedGroups) > 0 && !slices.ContainsFunc(u.Groups, func(g string) bool { return slices.Contains(a.cfg.AllowedGroups, g) }) {
		return nil, errors.New("user is not in an allowed group")
	}
	u.Admin = slices.ContainsFunc(u.Groups, func(g string) bool { return slices.Contains(a.cfg.AdminGroups, g) })
	return u, nil
}

// Authenticate returns the user for a request from a session cookie or a
// bearer token. It returns nil if the request is not authenticated.
func (a *Authenticator) Authenticate(r *http.Request) *User {
	if h := r.Header.Get("Authorization"); h != "" {
		tok, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return nil
		}
		return a.bearer(r.Context(), strings.TrimSpace(tok))
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	var u User
	if a.session.open(c.Value, &u) != nil {
		return nil
	}
	return &u
}

// bearer accepts an ID token issued to this client, or any access token
// that the provider's userinfo endpoint accepts.
func (a *Authenticator) bearer(ctx context.Context, tok string) *User {
	key := sha256.Sum256([]byte(tok))
	now := time.Now()
	a.cacheMu.Lock()
	if c, ok := a.cache[key]; ok && now.Before(c.exp) {
		a.cacheMu.Unlock()
		return c.user
	}
	a.cacheMu.Unlock()

	// The token must be a JWT signed by the issuer with this client in its audience.
	idt, err := a.verifier.Verify(ctx, tok)
	if err != nil {
		return nil
	}
	claims := map[string]any{}
	if idt.Claims(&claims) != nil {
		return nil
	}
	exp := now.Add(5 * time.Minute)
	if idt.Expiry.Before(exp) {
		exp = idt.Expiry
	}
	// Access tokens usually lack profile claims. Fill them in from userinfo.
	if _, ok := claims[a.cfg.UsernameClaim]; !ok {
		ui, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tok, TokenType: "Bearer"}))
		if err != nil || ui.Subject != idt.Subject {
			return nil
		}
		extra := map[string]any{}
		if ui.Claims(&extra) == nil {
			for k, v := range extra {
				if _, ok := claims[k]; !ok {
					claims[k] = v
				}
			}
		}
	}
	u, err := a.userFromClaims(claims)
	if err != nil {
		return nil
	}
	a.cacheMu.Lock()
	if len(a.cache) > 10000 {
		for k, c := range a.cache {
			if now.After(c.exp) {
				delete(a.cache, k)
			}
		}
	}
	a.cache[key] = cachedUser{user: u, exp: exp}
	a.cacheMu.Unlock()
	return u
}

// ProviderInfo is exposed so CLI clients can discover the issuer.
func (a *Authenticator) ProviderInfo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"issuer": a.cfg.Issuer, "client_id": a.cfg.ClientID})
}
