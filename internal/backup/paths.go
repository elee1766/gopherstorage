package backup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/elee1766/gopherstorage/internal/config"
)

// ValidateDestination rejects existing destinations and any path overlapping
// the live metadata or filesystem blob directory.
func ValidateDestination(cfg *config.Config, destination string) error {
	if cfg == nil || destination == "" {
		return errors.New("backup requires config and a destination")
	}
	dest, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(dest))
	if err != nil {
		return fmt.Errorf("resolve backup parent: %w", err)
	}
	dest = filepath.Join(parent, filepath.Base(dest))
	if _, err := os.Lstat(dest); err == nil {
		return fmt.Errorf("backup destination already exists: %s", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check backup destination: %w", err)
	}
	for _, source := range []string{cfg.DataDir, cfg.Storage.Path} {
		if source == "" {
			continue
		}
		resolved, err := resolvePath(source)
		if err != nil {
			return fmt.Errorf("resolve source path %q: %w", source, err)
		}
		if within(dest, resolved) || within(resolved, dest) {
			return fmt.Errorf("backup destination must be outside source directory %s", resolved)
		}
	}
	return nil
}

func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func resolvePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(abs)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", err
		}
		suffix = append(suffix, filepath.Base(abs))
		abs = parent
	}
}
