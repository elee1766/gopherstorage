// Package config loads the gopherstorage YAML configuration.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

type Config struct {
	Listen string `yaml:"listen"`
	// PublicURL is the address users open. remoteStorage addresses are
	// user@<host of PublicURL>.
	PublicURL string `yaml:"public_url"`
	// DataDir holds the metadata database and, by default, blobs.
	DataDir string `yaml:"data_dir"`

	OIDC    OIDC    `yaml:"oidc"`
	Session Session `yaml:"session"`
	Storage Storage `yaml:"storage"`
	Tokens  Tokens  `yaml:"tokens"`
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
	DefaultQuotaBytes int64 `yaml:"default_quota_bytes"`
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
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Config, error) {
	expanded, err := expandEnv(string(raw))
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
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
		c.Listen = ":8080"
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
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
}

// Host is the host[:port] of PublicURL, used in user addresses.
func (c *Config) Host() string {
	u, _ := url.Parse(c.PublicURL)
	return u.Host
}

func (c *Config) Validate() error {
	var errs []error
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		errs = append(errs, errors.New("public_url must be an absolute http(s) URL without a path"))
	}
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" {
		errs = append(errs, errors.New("oidc.issuer and oidc.client_id are required"))
	}
	if len(c.Session.Secret) < 32 {
		errs = append(errs, errors.New("session.secret must be at least 32 characters"))
	}
	switch c.Storage.Backend {
	case "filesystem":
	case "s3":
		if c.Storage.S3.Bucket == "" {
			errs = append(errs, errors.New("storage.s3.bucket is required"))
		}
	default:
		errs = append(errs, fmt.Errorf("storage.backend %q: want filesystem or s3", c.Storage.Backend))
	}
	if c.Storage.MaxDocumentBytes < 0 || c.Storage.DefaultQuotaBytes < 0 {
		errs = append(errs, errors.New("storage limits must not be negative"))
	}
	return errors.Join(errs...)
}

// IsAdmin reports whether any of groups is an admin group.
func (o OIDC) IsAdmin(groups []string) bool {
	return slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(o.AdminGroups, g) })
}
