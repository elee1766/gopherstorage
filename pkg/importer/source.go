package importer

import (
	"errors"
	"os"
	"sync"
)

var ErrSourceClosed = errors.New("import source is closed")

// Source pins an opened source directory. RunSource duplicates its directory
// handle, so the caller may close Source after the run returns.
type Source struct {
	mu   sync.Mutex
	root *importRoot
	path string
}

// OpenSource securely opens a source directory for import.
func OpenSource(path string) (*Source, error) {
	root, err := openImportRoot(path)
	if err != nil {
		return nil, err
	}
	return &Source{root: root, path: path}, nil
}

// Stat reports metadata for the pinned source directory.
func (s *Source) Stat() (os.FileInfo, error) {
	if s == nil {
		return nil, errors.New("nil import source")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil, ErrSourceClosed
	}
	return s.root.stat()
}

// Close releases the pinned directory handle.
func (s *Source) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root != nil {
		s.root.close()
		s.root = nil
	}
	return nil
}

func (s *Source) cloneRoot() (*importRoot, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil, "", ErrSourceClosed
	}
	root, err := s.root.clone()
	return root, s.path, err
}
