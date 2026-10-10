package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const secureConfig = `public_url: https://storage.example.com
oidc:
  issuer: https://id.example.com
  client_id: storage
session:
  secret: 01234567890123456789012345678901
`

func TestConfigRejectsUnsafeTransports(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"public HTTP", strings.Replace(secureConfig, "https://storage.example.com", "http://storage.example.com", 1)},
		{"issuer HTTP", strings.Replace(secureConfig, "https://id.example.com", "http://id.example.com", 1)},
		{"URL credentials", strings.Replace(secureConfig, "https://storage.example.com", "https://user:password@storage.example.com", 1)},
		{"URL query", strings.Replace(secureConfig, "https://storage.example.com", "https://storage.example.com?token=secret", 1)},
		{"public listener for local HTTP", "listen: ':8080'\n" + strings.Replace(secureConfig, "https://storage.example.com", "http://127.0.0.1:8080", 1)},
		{"negative token TTL", secureConfig + "tokens:\n  ttl: -1h\n"},
		{"negative session TTL", strings.Replace(secureConfig, "session:\n", "session:\n  max_age: -1h\n", 1)},
		{"nonprivate data root", secureConfig + "data_dir: /\n"},
		{"S3 credential transport", secureConfig + "storage:\n  backend: s3\n  s3:\n    bucket: documents\n    endpoint: http://s3.example.com\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse([]byte(c.raw)); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestConfigDefaultsAndExplicitOptIns(t *testing.T) {
	cfg, err := Parse([]byte(secureConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:8080" || cfg.Storage.MaxDocumentBytes != 64<<20 || cfg.Storage.DefaultQuotaBytes != 1<<30 || cfg.Tokens.TTL != 90*24*time.Hour || cfg.Tokens.AllowImplicit || cfg.View.AllowSameOrigin {
		t.Fatalf("unsafe defaults: %+v", cfg)
	}
	if cfg.HTTP.MaxConcurrentRequests <= 0 || cfg.HTTP.RequestTimeout <= 0 || cfg.Storage.MaxStagingBytes <= 0 || cfg.Storage.MaxNodes <= 0 {
		t.Fatal("resource admission limits are not finite")
	}
	raw := "allow_insecure_http: true\n" + strings.ReplaceAll(secureConfig, "https://", "http://") + `storage:
  max_document_bytes: 0
  default_quota_bytes: 0
tokens:
  ttl: 0s
  allow_implicit: true
view:
  allow_same_origin: true
`
	cfg, err = Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.MaxDocumentBytes != 0 || cfg.Storage.DefaultQuotaBytes != 0 || cfg.Tokens.TTL != 0 || !cfg.Tokens.AllowImplicit || !cfg.View.AllowSameOrigin {
		t.Fatal("explicit opt-ins were replaced by defaults")
	}
}

func TestLoadRejectsWritableConfiguration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(secureConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("world-writable configuration accepted")
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
}
