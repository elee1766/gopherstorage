package blob

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type interruptedUploadReader struct {
	sent bool
}

func TestFilesystemLegacyTemporaryCleanup(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFilesystem(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old := time.Now().Add(-48 * time.Hour)
	files := []struct {
		name string
		aged bool
	}{
		{"0123456789abcdef", true},
		{"fedcba9876543210", false},
		{"0123456789abcdef0123456789abcdef", true},
	}
	for _, f := range files {
		p := filepath.Join(dir, "tmp", f.name)
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
		if f.aged {
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	if n, err := s.CleanupTemporary(context.Background(), 24*time.Hour); err != nil || n != 1 {
		t.Fatalf("legacy cleanup = %d, %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tmp", files[0].name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("aged legacy bytes were retained: %v", err)
	}
	for _, f := range files[1:] {
		if _, err := os.Stat(filepath.Join(dir, "tmp", f.name)); err != nil {
			t.Fatalf("active or metadata-tracked upload was removed: %v", err)
		}
	}
}

func (r *interruptedUploadReader) Read(p []byte) (int, error) {
	if r.sent {
		os.Exit(23)
	}
	r.sent = true
	return copy(p, "partial bytes"), nil
}

// Exercise an actual interrupted Put, not a reconstructed temporary filename.
func TestFilesystemInterruptedUpload(t *testing.T) {
	const key = "1234567890abcdef1234567890abcdef"
	if dir := os.Getenv("GS_FS_CRASH_TEST_DIR"); dir != "" {
		s, err := NewFilesystem(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(context.Background(), key, &interruptedUploadReader{}, -1); err != nil {
			t.Fatal(err)
		}
		t.Fatal("upload did not interrupt the process")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestFilesystemInterruptedUpload$")
	cmd.Env = append(os.Environ(), "GS_FS_CRASH_TEST_DIR="+dir)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("interrupted upload exit = %v, output %s", err, out)
	}
	s, err := NewFilesystem(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Open(context.Background(), key, -1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("interrupted upload became readable: %v", err)
	}
	if err := s.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "tmp"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("crashed upload bytes retained after cleanup: %d entries, %v", len(entries), err)
	}
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("blob directory exposed to other users: %v, %v", st, err)
	}
	if err := s.Put(context.Background(), key, strings.NewReader("abc"), 3); err != nil {
		t.Fatal(err)
	}
	st, err = os.Stat(filepath.Join(dir, shard(key)))
	if err != nil || st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("blob exposed to other users: %v, %v", st, err)
	}
}
