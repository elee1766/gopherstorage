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
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
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

var configDefaults = map[string]any{
	"oidc":    map[string]any{"scopes": []string{"openid", "profile", "email", "groups"}},
	"session": map[string]any{"max_age": 12 * time.Hour},
	"storage": map[string]any{
		"max_document_bytes":     int64(64 << 20),
		"default_quota_bytes":    int64(1 << 30),
		"max_concurrent_uploads": 8,
		"max_staging_bytes":      int64(2 << 30),
		"max_nodes":              int64(100000),
		"max_folder_children":    10000,
	},
	"tokens": map[string]any{"ttl": 90 * 24 * time.Hour},
	"http": map[string]any{
		"max_concurrent_requests": 128,
		"rate_per_minute":         600,
		"rate_burst":              120,
		"max_rate_clients":        10000,
		"request_timeout":         5 * time.Minute,
	},
}

type configYAMLParser struct{}

func (configYAMLParser) Unmarshal(raw []byte) (map[string]any, error) {
	values := make(map[string]any)
	if err := yaml.Unmarshal(raw, &values); err != nil {
		return nil, errors.New("invalid YAML")
	}
	if err := validateYAMLKeys(values, reflect.TypeOf(Config{}), ""); err != nil {
		return nil, err
	}
	return values, nil
}

func (configYAMLParser) Marshal(values map[string]any) ([]byte, error) {
	return yaml.Marshal(values)
}

func validateYAMLKeys(values map[string]any, typ reflect.Type, prefix string) error {
	fields := make(map[string]reflect.Type, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name != "" && name != "-" {
			fields[name] = f.Type
		}
	}
	for name, value := range values {
		fieldType, ok := fields[name]
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		if !ok {
			return fmt.Errorf("unknown config key %q", path)
		}
		if value == nil {
			return fmt.Errorf("config key %q must not be null", path)
		}
		if fieldType.Kind() != reflect.Struct || fieldType == reflect.TypeOf(time.Duration(0)) {
			continue
		}
		nested, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("config key %q must be a mapping", path)
		}
		if err := validateYAMLKeys(nested, fieldType, path); err != nil {
			return err
		}
	}
	return nil
}

func expandConfigValues(k *koanf.Koanf, overridden map[string]struct{}) error {
	var missing []string
	var expand func(any) any
	expand = func(value any) any {
		switch value := value.(type) {
		case []any:
			for i := range value {
				value[i] = expand(value[i])
			}
			return value
		case []string:
			for i := range value {
				value[i] = expand(value[i]).(string)
			}
			return value
		case string:
			return envRef.ReplaceAllStringFunc(value, func(match string) string {
				name := envRef.FindStringSubmatch(match)[1]
				replacement, ok := os.LookupEnv(name)
				if !ok {
					missing = append(missing, name)
				}
				return replacement
			})
		default:
			return value
		}
	}
	for _, key := range k.Keys() {
		if _, skip := overridden[key]; skip {
			continue
		}
		value := k.Get(key)
		switch value.(type) {
		case string, []string, []any:
		default:
			continue
		}
		if err := k.Set(key, expand(value)); err != nil {
			return fmt.Errorf("expand config value for %s: %w", key, err)
		}
	}
	if len(missing) != 0 {
		slices.Sort(missing)
		missing = slices.Compact(missing)
		return fmt.Errorf("unset environment variables: %s", strings.Join(missing, ", "))
	}
	return nil
}

func Load(path string) (*Config, error) {
	if path == "" {
		return Parse(nil)
	}
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
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(configDefaults, "."), nil); err != nil {
		return nil, fmt.Errorf("load config defaults: %w", err)
	}
	if len(raw) != 0 {
		if err := k.Load(rawbytes.Provider(raw), configYAMLParser{}); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	overridden, err := loadEnvironment(k)
	if err != nil {
		return nil, err
	}
	if err := expandConfigValues(k, overridden); err != nil {
		return nil, err
	}
	encoded, err := k.Marshal(configYAMLParser{})
	if err != nil {
		return nil, errors.New("decode config: invalid values")
	}
	cfg := new(Config)
	if err := yaml.UnmarshalWithOptions(encoded, cfg, yaml.DisallowUnknownField()); err != nil {
		return nil, errors.New("decode config: invalid values")
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
	if c.Storage.Backend == "" {
		c.Storage.Backend = "filesystem"
	}
	if c.Session.MaxAge == 0 {
		c.Session.MaxAge = 12 * time.Hour
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
