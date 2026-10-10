package oauth

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseRequiresImplicitOptInAndS256PKCE(t *testing.T) {
	parse := func(allowImplicit bool, query string) (*request, *httptest.ResponseRecorder) {
		t.Helper()
		s := &Server{AllowImplicit: allowImplicit}
		r := httptest.NewRequest("GET", "/oauth/authorize?"+query, nil)
		r.ParseForm()
		w := httptest.NewRecorder()
		q, ok := s.parse(w, r)
		if ok {
			t.Fatal("parse accepted request unexpectedly")
		}
		return q, w
	}

	_, w := parse(false, "response_type=token&client_id=https%3A%2F%2Fapp.example&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=notes%3Ar")
	if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "error=unsupported_response_type") {
		t.Fatalf("implicit default: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}

	challenge := strings.Repeat("A", 43)
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {"https://app.example"},
		"redirect_uri":          {"https://app.example/cb"},
		"scope":                 {"notes:r"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	r := httptest.NewRequest("GET", "/oauth/authorize?"+query, nil)
	r.ParseForm()
	w = httptest.NewRecorder()
	q, ok := (&Server{}).parse(w, r)
	if !ok || w.Code != 200 {
		t.Fatalf("valid S256 code flow rejected: q=%v status=%d", q, w.Code)
	}
	for _, method := range []string{"", "plain"} {
		v := url.Values{}
		v.Set("response_type", "code")
		v.Set("client_id", "https://app.example")
		v.Set("redirect_uri", "https://app.example/cb")
		v.Set("scope", "notes:r")
		v.Set("code_challenge", challenge)
		if method != "" {
			v.Set("code_challenge_method", method)
		}
		r := httptest.NewRequest("GET", "/oauth/authorize?"+v.Encode(), nil)
		r.ParseForm()
		w := httptest.NewRecorder()
		if _, ok := (&Server{}).parse(w, r); ok || !strings.Contains(w.Header().Get("Location"), "error=invalid_request") {
			t.Errorf("PKCE method %q was accepted: status=%d location=%q", method, w.Code, w.Header().Get("Location"))
		}
	}
}

func TestParseAllowsImplicitOnlyWhenConfigured(t *testing.T) {
	r := httptest.NewRequest("GET", "/oauth/authorize?response_type=token&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=notes%3Ar", nil)
	r.ParseForm()
	if q, ok := (&Server{AllowImplicit: true}).parse(httptest.NewRecorder(), r); !ok || q.ResponseType != "token" {
		t.Fatalf("explicitly enabled implicit request rejected: q=%v ok=%t", q, ok)
	}
}
