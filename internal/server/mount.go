package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/elee1766/gopherstorage/internal/auth"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/storage"
)

type mount struct {
	cfg     config.Mount
	backend storage.Backend
}

// matches reports whether the user satisfies any rule.
func matches(u *auth.User, rules []string) bool {
	for _, rule := range rules {
		if rule == "*" {
			return true
		}
		kind, val, _ := strings.Cut(rule, ":")
		switch kind {
		case "user":
			if u.Username == val {
				return true
			}
		case "sub":
			if u.Subject == val {
				return true
			}
		case "email":
			if u.Email != "" && strings.EqualFold(u.Email, val) {
				return true
			}
		case "group":
			if slices.Contains(u.Groups, val) {
				return true
			}
		}
	}
	return false
}

func (m *mount) canRead(u *auth.User) bool {
	return u.Admin || matches(u, m.cfg.Read) || matches(u, m.cfg.Write)
}

func (m *mount) canWrite(u *auth.User) bool {
	return u.Admin || matches(u, m.cfg.Write)
}

var errBadIdentity = errors.New("user identity cannot be used as a path segment")

func safeSegment(v string) (string, error) {
	c, err := storage.Clean(v)
	if err != nil || c != v || v == "" || strings.Contains(v, "/") || strings.HasPrefix(v, ".") {
		return "", fmt.Errorf("%w: %q", errBadIdentity, v)
	}
	return v, nil
}

// resolve returns the backend scoped to the mount root for this user.
func (m *mount) resolve(u *auth.User) (storage.Backend, error) {
	p := m.cfg.Path
	if m.cfg.PerUser() {
		for _, kv := range [][2]string{{"{username}", u.Username}, {"{sub}", u.Subject}, {"{email}", strings.ToLower(u.Email)}} {
			if !strings.Contains(p, kv[0]) {
				continue
			}
			v, err := safeSegment(kv[1])
			if err != nil {
				return nil, err
			}
			p = strings.ReplaceAll(p, kv[0], v)
		}
	}
	clean, err := storage.Clean(p)
	if err != nil {
		return nil, err
	}
	return storage.Prefixed(m.backend, clean), nil
}
