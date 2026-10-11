//go:build linux

package importer

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

type importRoot struct{ fd int }

func openImportRoot(source string) (*importRoot, error) {
	abs, err := filepath.Abs(source)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	fd, err := unix.Open(string(os.PathSeparator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	for _, part := range strings.Split(strings.TrimPrefix(abs, string(os.PathSeparator)), string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open import root component %q: %w", part, openErr)
		}
		fd = next
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		return nil, fmt.Errorf("source root is not a directory")
	}
	return &importRoot{fd: fd}, nil
}
func (r *importRoot) close()       { _ = unix.Close(r.fd) }
func splitRel(rel string) []string { return strings.Split(rel, string(filepath.Separator)) }
func (r *importRoot) clone() (*importRoot, error) {
	fd, err := unix.Dup(r.fd)
	if err != nil {
		return nil, err
	}
	return &importRoot{fd: fd}, nil
}
func (r *importRoot) stat() (os.FileInfo, error) {
	fd, err := unix.Dup(r.fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "source")
	defer f.Close()
	return f.Stat()
}
func (r *importRoot) openParent(rel string) (int, string, error) {
	parts := splitRel(rel)
	if rel == "" || filepath.IsAbs(rel) {
		return -1, "", fmt.Errorf("invalid source path")
	}
	fd, err := unix.Dup(r.fd)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		unix.Close(fd)
		if e != nil {
			return -1, "", e
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}
func (r *importRoot) openFile(rel string) (*os.File, os.FileInfo, error) {
	parent, name, err := r.openParent(rel)
	if err != nil {
		return nil, nil, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("source is not a regular file")
	}
	return f, st, nil
}
func (r *importRoot) statFile(rel string) (os.FileInfo, error) {
	f, st, err := r.openFile(rel)
	if f != nil {
		f.Close()
	}
	return st, err
}
func (r *importRoot) walk(ctx context.Context, jobs chan<- job, prefix string, results chan<- outcome) error {
	return r.walkDir(ctx, r.fd, "", prefix, jobs, results, 0)
}
func (r *importRoot) walkDir(ctx context.Context, fd int, rel, prefix string, jobs chan<- job, results chan<- outcome, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("source directory depth exceeds %d", maxDepth)
	}
	dup, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dup), "directory")
	defer dir.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := dir.ReadDir(readBatch)
		if err != nil && err != io.EOF {
			return err
		}
		done := err == io.EOF
		for _, entry := range entries {
			name := entry.Name()
			item := filepath.Join(rel, name)
			if !validSourceName(name) {
				return fmt.Errorf("invalid source name %q", name)
			}
			var st unix.Stat_t
			if e := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return e
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				if depth+1 > maxDepth {
					return fmt.Errorf("source directory depth exceeds %d", maxDepth)
				}
				dfd, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
				if e != nil {
					return e
				}
				var check unix.Stat_t
				e = unix.Fstat(dfd, &check)
				if e == nil && check.Mode&unix.S_IFMT != unix.S_IFDIR {
					e = fmt.Errorf("source entry changed type")
				}
				if e == nil {
					e = r.walkDir(ctx, dfd, item, prefix, jobs, results, depth+1)
				}
				unix.Close(dfd)
				if e != nil {
					return e
				}
			case unix.S_IFREG:
				remote := pathJoin(prefix, filepath.ToSlash(item))
				if e := validateRemote(remote); e != nil {
					return fmt.Errorf("invalid destination for %q: %w", item, e)
				}
				if st.Size < 0 {
					return fmt.Errorf("invalid source size for %q", item)
				}
				select {
				case jobs <- job{rel: item, path: remote}:
				case <-ctx.Done():
					return ctx.Err()
				}
			default:
				unsupportedPath := pathJoin(prefix, filepath.ToSlash(item))
				select {
				case results <- outcome{event: Event{Path: unsupportedPath, Action: ActionUnsupported}}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		if done {
			return nil
		}
	}
}
func validSourceName(s string) bool {
	if s == "" || s == "." || s == ".." || !utf8.ValidString(s) || strings.ContainsAny(s, "/\\") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func pathJoin(prefix, rel string) string {
	if prefix == "/" {
		return "/" + rel
	}
	return prefix + rel
}
