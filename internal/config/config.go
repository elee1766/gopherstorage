// Package config loads the gopherstorage YAML configuration.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

type Config struct {
	Listen    string `yaml:"listen"`
	PublicURL string `yaml:"public_url"`
	// MaxUploadBytes limits a single upload. 0 means unlimited.
	MaxUploadBytes int64 `yaml:"max_upload_bytes"`

	OIDC     OIDC               `yaml:"oidc"`
	Session  Session            `yaml:"session"`
	Backends map[string]Backend `yaml:"backends"`
	Mounts   []Mount            `yaml:"mounts"`
}

type OIDC struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
	// UsernameClaim is used for {username} in mount paths and user: rules.
	UsernameClaim string `yaml:"username_claim"`
	GroupsClaim   string `yaml:"groups_claim"`
	// AdminGroups get read and write access to every mount.
	AdminGroups []string `yaml:"admin_groups"`
	// AllowedGroups, if set, restricts login to members of these groups.
	AllowedGroups []string `yaml:"allowed_groups"`
}

type Session struct {
	// Secret encrypts session cookies. At least 32 characters.
	Secret string        `yaml:"secret"`
	MaxAge time.Duration `yaml:"max_age"`
}

type Backend struct {
	Type string `yaml:"type"` // filesystem | s3

	// filesystem
	Path string `yaml:"path"`

	// s3
	Endpoint     string `yaml:"endpoint"`
	Region       string `yaml:"region"`
	Bucket       string `yaml:"bucket"`
	Prefix       string `yaml:"prefix"`
	AccessKey    string `yaml:"access_key"`
	SecretKey    string `yaml:"secret_key"`
	SessionToken string `yaml:"session_token"`
	Insecure     bool   `yaml:"insecure"` // use http instead of https
	// PathStyle forces path-style bucket addressing (needed by most self-hosted S3 servers).
	PathStyle bool `yaml:"path_style"`
}

type Mount struct {
	Name    string `yaml:"name"`
	Backend string `yaml:"backend"`
	// Path inside the backend. May contain {username}, {sub} or {email},
	// which makes the mount per-user.
	Path  string   `yaml:"path"`
	Read  []string `yaml:"read"`
	Write []string `yaml:"write"`
}

func (m Mount) PerUser() bool {
	return strings.Contains(m.Path, "{username}") || strings.Contains(m.Path, "{sub}") || strings.Contains(m.Path, "{email}")
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
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
}

var mountName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func (c *Config) Validate() error {
	var errs []error
	if u, err := url.Parse(c.PublicURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, errors.New("public_url must be an absolute http(s) URL"))
	}
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" {
		errs = append(errs, errors.New("oidc.issuer and oidc.client_id are required"))
	}
	if len(c.Session.Secret) < 32 {
		errs = append(errs, errors.New("session.secret must be at least 32 characters"))
	}
	for name, b := range c.Backends {
		switch b.Type {
		case "filesystem":
			if b.Path == "" {
				errs = append(errs, fmt.Errorf("backend %q: path is required", name))
			}
		case "s3":
			if b.Bucket == "" {
				errs = append(errs, fmt.Errorf("backend %q: bucket is required", name))
			}
		default:
			errs = append(errs, fmt.Errorf("backend %q: unknown type %q (want filesystem or s3)", name, b.Type))
		}
	}
	if len(c.Mounts) == 0 {
		errs = append(errs, errors.New("at least one mount is required"))
	}
	seen := map[string]bool{}
	for i, m := range c.Mounts {
		if !mountName.MatchString(m.Name) {
			errs = append(errs, fmt.Errorf("mounts[%d]: invalid name %q", i, m.Name))
		}
		if seen[m.Name] {
			errs = append(errs, fmt.Errorf("mounts[%d]: duplicate name %q", i, m.Name))
		}
		seen[m.Name] = true
		if _, ok := c.Backends[m.Backend]; !ok {
			errs = append(errs, fmt.Errorf("mount %q: unknown backend %q", m.Name, m.Backend))
		}
		for _, rule := range append(append([]string{}, m.Read...), m.Write...) {
			if err := ValidateRule(rule); err != nil {
				errs = append(errs, fmt.Errorf("mount %q: %w", m.Name, err))
			}
		}
	}
	return errors.Join(errs...)
}

// ValidateRule checks an access rule: "*", "user:<name>", "sub:<id>", "email:<addr>" or "group:<name>".
func ValidateRule(rule string) error {
	if rule == "*" {
		return nil
	}
	kind, val, ok := strings.Cut(rule, ":")
	if !ok || val == "" {
		return fmt.Errorf("invalid access rule %q", rule)
	}
	switch kind {
	case "user", "sub", "email", "group":
		return nil
	}
	return fmt.Errorf("invalid access rule %q: unknown kind %q", rule, kind)
}
