package auth

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/elee1766/gopherstorage/internal/config"
	"golang.org/x/oauth2"
)

func TestCallbackBadStateKeepsFlowCookie(t *testing.T) {
	flow, err := newSealer(strings.Repeat("f", 32), "flow")
	if err != nil {
		t.Fatal(err)
	}
	a := &Authenticator{
		flow: flow,
		oauth: oauth2.Config{
			ClientID:    "client",
			RedirectURL: "https://storage.example/auth/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://id.example/authorize"},
		},
	}

	loginReq := httptest.NewRequest("GET", "https://storage.example/auth/login", nil)
	loginRes := httptest.NewRecorder()
	a.Login(loginRes, loginReq)
	if loginRes.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("login Cache-Control = %q", loginRes.Header().Get("Cache-Control"))
	}
	cookies := loginRes.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != flowCookie || cookies[0].Value == "" {
		t.Fatalf("login flow cookie = %v", cookies)
	}

	callbackReq := httptest.NewRequest("GET", "https://storage.example/auth/callback?state=wrong&code=unused", nil)
	callbackReq.AddCookie(cookies[0])
	callbackRes := httptest.NewRecorder()
	a.Callback(callbackRes, callbackReq)
	if callbackRes.Code != 400 {
		t.Fatalf("callback status = %d, want 400", callbackRes.Code)
	}
	if callbackRes.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("callback Cache-Control = %q", callbackRes.Header().Get("Cache-Control"))
	}
	if values := callbackRes.Header().Values("Set-Cookie"); len(values) != 0 {
		t.Fatalf("bad-state callback changed cookies: %v", values)
	}
}

func TestLogoutPreservesProviderLogoutWithoutExternalFormRedirect(t *testing.T) {
	a := &Authenticator{
		cfg:       config.OIDC{ClientID: "client"},
		publicURL: "https://storage.example",
		endSess:   "https://id.example/logout?tenant=main",
	}

	noJSReq := httptest.NewRequest("POST", "https://storage.example/auth/logout", nil)
	noJSRes := httptest.NewRecorder()
	a.Logout(noJSRes, noJSReq)
	if noJSRes.Code != 200 || !strings.Contains(noJSRes.Body.String(), `href="https://id.example/logout?`) || !strings.Contains(noJSRes.Body.String(), "client_id=client") || !strings.Contains(noJSRes.Body.String(), "post_logout_redirect_uri=https%3A%2F%2Fstorage.example%2F") {
		t.Fatalf("non-JS logout response: %d %s", noJSRes.Code, noJSRes.Body.String())
	}
	if noJSRes.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("non-JS logout Cache-Control = %q", noJSRes.Header().Get("Cache-Control"))
	}
	if !strings.Contains(noJSRes.Header().Get("Set-Cookie"), "gs_session=") {
		t.Fatal("non-JS logout did not clear the session cookie")
	}
	if !strings.Contains(noJSRes.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatalf("logout page CSP = %q", noJSRes.Header().Get("Content-Security-Policy"))
	}

	hxReq := httptest.NewRequest("POST", "https://storage.example/auth/logout", nil)
	hxReq.Header.Set("HX-Request", "true")
	hxRes := httptest.NewRecorder()
	a.Logout(hxRes, hxReq)
	if hxRes.Code != 200 || hxRes.Header().Get("HX-Redirect") == "" {
		t.Fatalf("htmx logout response: %d, HX-Redirect=%q", hxRes.Code, hxRes.Header().Get("HX-Redirect"))
	}
	if hxRes.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("htmx logout Cache-Control = %q", hxRes.Header().Get("Cache-Control"))
	}
	redirect, err := url.Parse(hxRes.Header().Get("HX-Redirect"))
	if err != nil || redirect.Host != "id.example" || redirect.Query().Get("client_id") != "client" || redirect.Query().Get("post_logout_redirect_uri") != "https://storage.example/" {
		t.Fatalf("provider logout URL = %q, err=%v", hxRes.Header().Get("HX-Redirect"), err)
	}
}
