// Package config loads the gopherstorage YAML configuration.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

type Config struct {
	Listen string `yaml:"listen"`
	// AllowInsecureHTTP is an explicit opt-in for local development without TLS.
	AllowInsecureHTTP bool `yaml:"allow_insecure_http"`
	// PublicURL is the address users open. remoteStorage addresses are
	// user@<host of PublicURL>.
	PublicURL string `yaml:"public_url"`
	// DataDir holds the metadata database and, by default, blobs.
	DataDir string `yaml:"data_dir"`

	OIDC    OIDC    `yaml:"oidc"`
	Session Session `yaml:"session"`
	Storage Storage `yaml:"storage"`
	Tokens  Tokens  `yaml:"tokens"`
	View    View    `yaml:"view"`
	HTTP    HTTP    `yaml:"http"`
}

// HTTP bounds admission and the lifetime of each request.
type HTTP struct {
	MaxConcurrentRequests int           `yaml:"max_concurrent_requests"`
	RatePerMinute         int           `yaml:"rate_per_minute"`
	RateBurst             int           `yaml:"rate_burst"`
	MaxRateClients        int           `yaml:"max_rate_clients"`
	RequestTimeout        time.Duration `yaml:"request_timeout"`
}

// View configures /view/, which shows public documents in browsers.
type View struct {
	// URL is an optional separate origin for /view/, e.g. https://share.example.com.
	// Point it at the same server. When set, /view/ only answers on that host.
	URL string `yaml:"url"`
	// AllowSameOrigin permits inline active content on the account origin.
	AllowSameOrigin bool `yaml:"allow_same_origin"`
	// CacheMaxAge lets browsers and proxies reuse responses without revalidating.
	// 0 means they revalidate every time (ETag), so edits show up immediately.
	CacheMaxAge time.Duration `yaml:"cache_max_age"`
}

// ViewHost is the host of View.URL, or "" if /view/ is served on every host.
func (c *Config) ViewHost() string {
	if c.View.URL == "" {
		return ""
	}
	u, _ := url.Parse(c.View.URL)
	return u.Host
}

type OIDC struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
	// UsernameClaim becomes the storage username (user@host).
	UsernameClaim string `yaml:"username_claim"`
	GroupsClaim   string `yaml:"groups_claim"`
	// AllowedGroups, if set, restricts login to members of these groups.
	AllowedGroups []string `yaml:"allowed_groups"`
	// AdminGroups can see all users and set quotas.
	AdminGroups []string `yaml:"admin_groups"`
}

type Session struct {
	// Secret encrypts session cookies. At least 32 characters.
	Secret string        `yaml:"secret"`
	MaxAge time.Duration `yaml:"max_age"`
}

type Storage struct {
	// Backend is "filesystem" or "s3".
	Backend string `yaml:"backend"`
	// Path of the filesystem blob directory. Default: <data_dir>/blobs.
	Path string `yaml:"path"`
	S3   S3     `yaml:"s3"`
	// MaxDocumentBytes limits a single document. 0 means unlimited.
	MaxDocumentBytes int64 `yaml:"max_document_bytes"`
	// DefaultQuotaBytes applies to users without their own quota. 0 means unlimited.
	DefaultQuotaBytes    int64 `yaml:"default_quota_bytes"`
	MaxConcurrentUploads int   `yaml:"max_concurrent_uploads"`
	MaxStagingBytes      int64 `yaml:"max_staging_bytes"`
	MaxNodes             int64 `yaml:"max_nodes"`
	MaxFolderChildren    int   `yaml:"max_folder_children"`
}

type S3 struct {
	// Endpoint for non-AWS servers. Empty means AWS S3.
	Endpoint     string `yaml:"endpoint"`
	Region       string `yaml:"region"`
	Bucket       string `yaml:"bucket"`
	Prefix       string `yaml:"prefix"`
	AccessKey    string `yaml:"access_key"`
	SecretKey    string `yaml:"secret_key"`
	SessionToken string `yaml:"session_token"`
	Insecure     bool   `yaml:"insecure"`
	PathStyle    bool   `yaml:"path_style"`
}

type Tokens struct {
	// TTL of access tokens issued to apps. 0 means they do not expire
	// (remoteStorage apps have no refresh flow; users revoke in the UI).
	TTL time.Duration `yaml:"ttl"`
	// AllowImplicit enables the legacy fragment-based flow instead of S256 PKCE.
	AllowImplicit bool `yaml:"allow_implicit"`
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${VAR} references outside comment lines. ${VAR} with VAR unset is an error.
func expandEnv(s string) (string, error) {
	var missing []string
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		lines[i] = envRef.ReplaceAllStringFunc(line, func(m string) string {
			name := envRef.FindStringSubmatch(m)[1]
			v, ok := os.LookupEnv(name)
			if !ok {
				missing = append(missing, name)
			}
			return v
		})
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("unset environment variables: %s", strings.Join(missing, ", "))
	}
	return strings.Join(lines, "\n"), nil
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("config must be a regular file and must not be group- or world-writable")
	}
	if st.Size() > 1<<20 {
		return nil, errors.New("config exceeds 1 MiB")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("config exceeds 1 MiB")
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Config, error) {
	expanded, err := expandEnv(string(raw))
	if err != nil {
		return nil, err
	}
	// Setting these before decoding preserves an explicit zero as unlimited.
	cfg := &Config{
		Storage: Storage{MaxDocumentBytes: 64 << 20, DefaultQuotaBytes: 1 << 30},
		Tokens:  Tokens{TTL: 90 * 24 * time.Hour},
	}
	if err := yaml.UnmarshalWithOptions([]byte(expanded), cfg, yaml.DisallowUnknownField()); err != nil {
		return nil, fmt.Errorf("parse config:\n%s", yaml.FormatError(err, false, true))
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if len(c.OIDC.Scopes) == 0 {
		c.OIDC.Scopes = []string{"openid", "profile", "email", "groups"}
	}
	if c.OIDC.UsernameClaim == "" {
		c.OIDC.UsernameClaim = "preferred_username"
	}
	if c.OIDC.GroupsClaim == "" {
		c.OIDC.GroupsClaim = "groups"
	}
	if c.Session.MaxAge == 0 {
		c.Session.MaxAge = 12 * time.Hour
	}
	if c.Storage.Backend == "" {
		c.Storage.Backend = "filesystem"
	}
	if c.Storage.Backend == "filesystem" && c.Storage.Path == "" {
		c.Storage.Path = c.DataDir + "/blobs"
	}
	if c.Storage.MaxConcurrentUploads == 0 {
		c.Storage.MaxConcurrentUploads = 8
	}
	if c.Storage.MaxStagingBytes == 0 {
		c.Storage.MaxStagingBytes = 2 << 30
	}
	if c.Storage.MaxNodes == 0 {
		c.Storage.MaxNodes = 100000
	}
	if c.Storage.MaxFolderChildren == 0 {
		c.Storage.MaxFolderChildren = 10000
	}
	if c.HTTP.MaxConcurrentRequests == 0 {
		c.HTTP.MaxConcurrentRequests = 128
	}
	if c.HTTP.RatePerMinute == 0 {
		c.HTTP.RatePerMinute = 600
	}
	if c.HTTP.RateBurst == 0 {
		c.HTTP.RateBurst = 120
	}
	if c.HTTP.MaxRateClients == 0 {
		c.HTTP.MaxRateClients = 10000
	}
	if c.HTTP.RequestTimeout == 0 {
		c.HTTP.RequestTimeout = 5 * time.Minute
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	c.View.URL = strings.TrimRight(c.View.URL, "/")
}

// Host is the host[:port] of PublicURL, used in user addresses.
func (c *Config) Host() string {
	u, _ := url.Parse(c.PublicURL)
	return u.Host
}

func (c *Config) Validate() error {
	var errs []error
	for _, p := range []string{c.DataDir, c.Storage.Path} {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if resolved, resolveErr := filepath.EvalSymlinks(abs); resolveErr == nil {
			abs = resolved
		}
		cwd, _ := os.Getwd()
		home, _ := os.UserHomeDir()
		if err != nil || abs == string(filepath.Separator) || abs == cwd || abs == home {
			errs = append(errs, errors.New("data_dir and storage.path must use dedicated directories, not root, home or the working directory"))
		}
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || !validOrigin(u) {
		errs = append(errs, errors.New("public_url must be an absolute http(s) URL without a path"))
	} else if u.Scheme == "http" && !c.AllowInsecureHTTP && !loopbackHost(u.Hostname()) {
		errs = append(errs, errors.New("public_url must use HTTPS outside loopback (allow_insecure_http is for development only)"))
	}
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" {
		errs = append(errs, errors.New("oidc.issuer and oidc.client_id are required"))
	}
	issuer, issuerErr := url.Parse(c.OIDC.Issuer)
	if issuerErr != nil || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || (issuer.Scheme != "https" && issuer.Scheme != "http") {
		errs = append(errs, errors.New("oidc.issuer must be an absolute HTTP(S) URL without credentials, query or fragment"))
	} else if issuer.Scheme != "https" && !loopbackHost(issuer.Hostname()) && !c.AllowInsecureHTTP {
		errs = append(errs, errors.New("oidc.issuer must use HTTPS outside loopback"))
	}
	listenHost, _, listenErr := net.SplitHostPort(c.Listen)
	if listenErr != nil {
		errs = append(errs, errors.New("listen must be a host:port address"))
	} else if u != nil && u.Scheme == "http" && !loopbackHost(listenHost) && !c.AllowInsecureHTTP {
		errs = append(errs, errors.New("a plain HTTP public_url requires a loopback listener or explicit allow_insecure_http"))
	}
	if len(c.Session.Secret) < 32 {
		errs = append(errs, errors.New("session.secret must be at least 32 characters"))
	}
	if c.Session.MaxAge <= 0 || c.Session.MaxAge > 30*24*time.Hour {
		errs = append(errs, errors.New("session.max_age must be positive and at most 30 days"))
	}
	if c.Tokens.TTL < 0 {
		errs = append(errs, errors.New("tokens.ttl must not be negative"))
	}
	switch c.Storage.Backend {
	case "filesystem":
	case "s3":
		if c.Storage.S3.Bucket == "" {
			errs = append(errs, errors.New("storage.s3.bucket is required"))
		}
		if c.Storage.S3.Endpoint != "" {
			ep := c.Storage.S3.Endpoint
			if !strings.Contains(ep, "://") {
				ep = "https://" + ep
			}
			endpoint, err := url.Parse(ep)
			if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
				errs = append(errs, errors.New("storage.s3.endpoint must be an HTTP(S) URL without credentials, query or fragment"))
			} else if endpoint.Scheme == "http" && !loopbackHost(endpoint.Hostname()) && !c.Storage.S3.Insecure {
				errs = append(errs, errors.New("plain HTTP storage.s3.endpoint requires storage.s3.insecure: true"))
			}
		}
	default:
		errs = append(errs, fmt.Errorf("storage.backend %q: want filesystem or s3", c.Storage.Backend))
	}
	if c.Storage.MaxDocumentBytes < 0 || c.Storage.DefaultQuotaBytes < 0 {
		errs = append(errs, errors.New("storage limits must not be negative"))
	}
	if c.Storage.MaxConcurrentUploads <= 0 || c.Storage.MaxConcurrentUploads > 64 || c.Storage.MaxStagingBytes <= 0 || c.Storage.MaxNodes <= 0 || c.Storage.MaxNodes > 1000000 || c.Storage.MaxFolderChildren <= 0 || c.Storage.MaxFolderChildren > 50000 {
		errs = append(errs, errors.New("storage limits must be positive, with at most 64 upload slots, 1000000 nodes and 50000 children"))
	}
	if c.HTTP.MaxConcurrentRequests <= 0 || c.HTTP.MaxConcurrentRequests > 4096 || c.HTTP.RatePerMinute <= 0 || c.HTTP.RatePerMinute > 100000 || c.HTTP.RateBurst <= 0 || c.HTTP.RateBurst > 10000 || c.HTTP.MaxRateClients <= 0 || c.HTTP.MaxRateClients > 100000 || c.HTTP.RequestTimeout <= 0 || c.HTTP.RequestTimeout > 5*time.Minute {
		errs = append(errs, errors.New("http limits must be positive and within 4096 requests, 100000 requests/minute, 10000 burst, 100000 client keys and 5m"))
	}
	if c.View.URL != "" {
		vu, err := url.Parse(c.View.URL)
		if err != nil || !validOrigin(vu) {
			errs = append(errs, errors.New("view.url must be an absolute http(s) URL without a path"))
		} else if u != nil && strings.EqualFold(vu.Host, u.Host) {
			errs = append(errs, errors.New("view.url must use a different host than public_url (or be left empty)"))
		}
		if err == nil && validOrigin(vu) && vu.Scheme == "http" && !loopbackHost(vu.Hostname()) && !c.AllowInsecureHTTP {
			errs = append(errs, errors.New("view.url must use HTTPS outside loopback"))
		}
	}
	if c.View.CacheMaxAge < 0 {
		errs = append(errs, errors.New("view.cache_max_age must not be negative"))
	}
	return errors.Join(errs...)
}

func validOrigin(u *url.URL) bool {
	return u != nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.Hostname() != "" && !strings.HasSuffix(u.Host, ":") && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery && (u.Path == "" || u.Path == "/")
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// IsAdmin reports whether any of groups is an admin group.
func (o OIDC) IsAdmin(groups []string) bool {
	return slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(o.AdminGroups, g) })
}
