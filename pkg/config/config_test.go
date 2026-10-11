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
	if cfg.Listen != "127.0.0.1:8080" || cfg.Storage.MaxDocumentBytes != 64<<20 || cfg.Storage.DefaultQuotaBytes != 1<<30 || cfg.Tokens.TTL != 90*24*time.Hour || cfg.Tokens.AllowImplicit {
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
`
	cfg, err = Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Storage.MaxDocumentBytes != 0 || cfg.Storage.DefaultQuotaBytes != 0 || cfg.Tokens.TTL != 0 || !cfg.Tokens.AllowImplicit {
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

func TestParseEnvironmentOverridesYAML(t *testing.T) {
	t.Setenv("GOPHERSTORAGE_PUBLIC_URL", "https://env.example.com/")
	t.Setenv("GOPHERSTORAGE_STORAGE_MAX_DOCUMENT_BYTES", "0")
	t.Setenv("GOPHERSTORAGE_TOKENS_TTL", "0s")
	t.Setenv("GOPHERSTORAGE_OIDC_ALLOWED_GROUPS", `[]`)
	t.Setenv("GOPHERSTORAGE_OIDC_ADMIN_GROUPS", `["ops,west","admins"]`)
	t.Setenv("GOPHERSTORAGE_OIDC_CLIENT_SECRET", `literal:${NOT_A_REFERENCE}/a:b?c=d#e`)
	t.Setenv("GOPHERSTORAGE_STORAGE_S3_BUCKET", "bucket-name")
	// A valid selector is not a config field and is ignored by Parse/Load.
	t.Setenv("GOPHERSTORAGE_CONFIG", "/does/not/need/to/exist")

	raw := strings.Replace(secureConfig, "client_id: storage", "client_id: storage\n  client_secret: ${MISSING_YAML_SECRET}\n  allowed_groups: [yaml-group]\n  admin_groups: [yaml-admin]", 1) + `storage:
  max_document_bytes: 123
tokens:
  ttl: 24h
`
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://env.example.com" || cfg.Storage.MaxDocumentBytes != 0 || cfg.Tokens.TTL != 0 {
		t.Fatalf("environment values did not override YAML or preserve zero: %+v", cfg)
	}
	if cfg.OIDC.AllowedGroups == nil || len(cfg.OIDC.AllowedGroups) != 0 {
		t.Fatalf("empty JSON array did not clear allowed groups: %#v", cfg.OIDC.AllowedGroups)
	}
	if strings.Join(cfg.OIDC.AdminGroups, "|") != "ops,west|admins" {
		t.Fatalf("unexpected admin groups: %#v", cfg.OIDC.AdminGroups)
	}
	if cfg.OIDC.ClientSecret != `literal:${NOT_A_REFERENCE}/a:b?c=d#e` {
		t.Fatalf("environment secret was modified: %q", cfg.OIDC.ClientSecret)
	}
	if cfg.Storage.S3.Bucket != "bucket-name" {
		t.Fatalf("nested underscore key did not map exactly: %q", cfg.Storage.S3.Bucket)
	}
}

func TestLoadWithoutPathUsesEnvironment(t *testing.T) {
	t.Setenv("GOPHERSTORAGE_CONFIG", "/missing/config.yaml")
	t.Setenv("GOPHERSTORAGE_PUBLIC_URL", "https://storage.example.com")
	t.Setenv("GOPHERSTORAGE_OIDC_ISSUER", "https://id.example.com")
	t.Setenv("GOPHERSTORAGE_OIDC_CLIENT_ID", "storage")
	t.Setenv("GOPHERSTORAGE_SESSION_SECRET", "01234567890123456789012345678901")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://storage.example.com" || cfg.OIDC.ClientID != "storage" {
		t.Fatalf("environment-only config not loaded: %+v", cfg)
	}
}

func TestParseRejectsInvalidAndUnknownEnvironmentValues(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
	}{
		{"unknown key", "GOPHERSTORAGE_STORAGE_S3_BUCKET_EXTRA", "bad"},
		{"removed view setting", "GOPHERSTORAGE_VIEW_URL", "https://share.example.com"},
		{"boolean", "GOPHERSTORAGE_ALLOW_INSECURE_HTTP", "sometimes"},
		{"integer", "GOPHERSTORAGE_STORAGE_MAX_DOCUMENT_BYTES", "many"},
		{"duration", "GOPHERSTORAGE_TOKENS_TTL", "soon"},
		{"list must be JSON array", "GOPHERSTORAGE_OIDC_ADMIN_GROUPS", "null"},
		{"list element type", "GOPHERSTORAGE_OIDC_ADMIN_GROUPS", `["ops",3]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, err := Parse([]byte(secureConfig)); err == nil {
				t.Fatal("invalid environment configuration accepted")
			}
		})
	}
}

func TestParseRejectsInvalidYAMLValues(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"null section", secureConfig + "storage: null\n"},
		{"wrong boolean type", secureConfig + "allow_insecure_http: perhaps\n"},
		{"wrong integer type", secureConfig + "storage:\n  max_document_bytes: many\n"},
		{"removed view section", secureConfig + "view:\n  url: https://share.example.com\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.raw)); err == nil {
				t.Fatal("invalid YAML value accepted")
			}
		})
	}
}

func TestYAMLSecretSubstitutionPreservesLiteralValue(t *testing.T) {
	secret := "colon: # comment\nquoted: \"value\" ${LITERAL}"
	t.Setenv("CONFIG_TEST_SECRET", secret)
	cfg, err := Parse([]byte(strings.Replace(secureConfig,
		"client_id: storage", "client_id: storage\n  client_secret: ${CONFIG_TEST_SECRET}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.ClientSecret != secret {
		t.Fatalf("YAML substitution changed literal secret: %q", cfg.OIDC.ClientSecret)
	}
}

func TestYAMLSecretSubstitutionRejectsMissingReference(t *testing.T) {
	if _, err := Parse([]byte(strings.Replace(secureConfig,
		"client_id: storage", "client_id: storage\n  client_secret: ${UNSET_SECRET}", 1))); err == nil || !strings.Contains(err.Error(), "UNSET_SECRET") {
		t.Fatalf("unset YAML substitution was not rejected: %v", err)
	}
}
