package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// conformance runs the same behavior checks against any Backend.
func conformance(t *testing.T, b Backend) {
	ctx := context.Background()
	put := func(p, body string) {
		t.Helper()
		if _, err := b.Put(ctx, p, strings.NewReader(body), int64(len(body)), ""); err != nil {
			t.Fatalf("put %s: %v", p, err)
		}
	}
	read := func(p string) string {
		t.Helper()
		r, _, err := b.Open(ctx, p)
		if err != nil {
			t.Fatalf("open %s: %v", p, err)
		}
		defer r.Close()
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		return string(data)
	}
	names := func(dir string) []string {
		t.Helper()
		es, err := b.List(ctx, dir)
		if err != nil {
			t.Fatalf("list %q: %v", dir, err)
		}
		var out []string
		for _, e := range es {
			n := e.Name
			if e.IsDir {
				n += "/"
			}
			out = append(out, n)
		}
		return out
	}
	expectErr := func(err, want error, what string) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Fatalf("%s: got %v, want %v", what, err, want)
		}
	}

	put("a/b/c.txt", "hello")
	if got := read("a/b/c.txt"); got != "hello" {
		t.Fatalf("read back %q", got)
	}
	e, err := b.Stat(ctx, "a/b/c.txt")
	if err != nil || e.IsDir || e.Size != 5 || e.Name != "c.txt" || e.Path != "a/b/c.txt" || e.ContentType != "text/plain; charset=utf-8" {
		t.Fatalf("stat file: %+v %v", e, err)
	}
	if e, err := b.Stat(ctx, "a"); err != nil || !e.IsDir {
		t.Fatalf("stat implicit dir: %+v %v", e, err)
	}
	if e, err := b.Stat(ctx, ""); err != nil || !e.IsDir {
		t.Fatalf("stat root: %+v %v", e, err)
	}
	_, err = b.Stat(ctx, "nope")
	expectErr(err, ErrNotExist, "stat missing")
	_, err = b.List(ctx, "nope")
	expectErr(err, ErrNotExist, "list missing")
	_, err = b.List(ctx, "a/b/c.txt")
	expectErr(err, ErrNotDir, "list file")
	_, _, err = b.Open(ctx, "a")
	expectErr(err, ErrIsDir, "open dir")
	_, _, err = b.Open(ctx, "nope")
	expectErr(err, ErrNotExist, "open missing")

	// Overwrite.
	put("a/b/c.txt", "world!")
	if got := read("a/b/c.txt"); got != "world!" {
		t.Fatalf("overwrite read back %q", got)
	}

	// Seek support for range requests.
	r, _, err := b.Open(ctx, "a/b/c.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Seek(2, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(r)
	r.Close()
	if string(rest) != "rld!" {
		t.Fatalf("seek read %q", rest)
	}

	// Unknown size upload.
	if _, err := b.Put(ctx, "stream.bin", io.LimitReader(strings.NewReader(strings.Repeat("x", 1000)), 1000), -1, ""); err != nil {
		t.Fatalf("put unknown size: %v", err)
	}
	if e, _ := b.Stat(ctx, "stream.bin"); e.Size != 1000 {
		t.Fatalf("unknown size upload stored %d bytes", e.Size)
	}

	// Writing over or under a file is rejected.
	_, err = b.Put(ctx, "a", strings.NewReader("x"), 1, "")
	expectErr(err, ErrIsDir, "put over dir")
	_, err = b.Put(ctx, "a/b/c.txt/d", strings.NewReader("x"), 1, "")
	expectErr(err, ErrNotDir, "put under file")
	expectErr(b.Mkdir(ctx, "a/b/c.txt"), ErrExist, "mkdir over file")

	// Empty directories persist and are listed.
	if err := b.Mkdir(ctx, "empty/nested"); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := b.Mkdir(ctx, "empty/nested"); err != nil {
		t.Fatalf("mkdir existing: %v", err)
	}
	if got := names("empty"); !slices.Equal(got, []string{"nested/"}) {
		t.Fatalf("list empty: %v", got)
	}
	if got := names("empty/nested"); len(got) != 0 {
		t.Fatalf("list nested: %v", got)
	}
	if got := names(""); !slices.Equal(got, []string{"a/", "empty/", "stream.bin"}) {
		t.Fatalf("list root: %v", got)
	}

	// Non-recursive delete of a non-empty dir fails.
	expectErr(b.Delete(ctx, "a", false), ErrNotEmpty, "delete non-empty")
	expectErr(b.Delete(ctx, "nope", false), ErrNotExist, "delete missing")

	// Deleting the last file keeps the parent directory.
	if err := b.Delete(ctx, "a/b/c.txt", false); err != nil {
		t.Fatalf("delete file: %v", err)
	}
	if e, err := b.Stat(ctx, "a/b"); err != nil || !e.IsDir {
		t.Fatalf("parent gone after delete: %v", err)
	}
	if err := b.Delete(ctx, "a/b", false); err != nil {
		t.Fatalf("delete empty dir: %v", err)
	}
	if got := names("a"); len(got) != 0 {
		t.Fatalf("a after delete: %v", got)
	}

	// Move file.
	put("m/one.txt", "1")
	if err := b.Move(ctx, "m/one.txt", "n/deep/uno.txt"); err != nil {
		t.Fatalf("move file: %v", err)
	}
	if got := read("n/deep/uno.txt"); got != "1" {
		t.Fatalf("moved content %q", got)
	}
	_, err = b.Stat(ctx, "m/one.txt")
	expectErr(err, ErrNotExist, "source after move")
	if e, err := b.Stat(ctx, "m"); err != nil || !e.IsDir {
		t.Fatalf("source parent gone after move: %v", err)
	}

	// Move directory tree, including empty subdirs.
	put("tree/x.txt", "x")
	put("tree/sub/y.txt", "y")
	if err := b.Mkdir(ctx, "tree/hollow"); err != nil {
		t.Fatal(err)
	}
	if err := b.Move(ctx, "tree", "moved/tree2"); err != nil {
		t.Fatalf("move dir: %v", err)
	}
	if got := names("moved/tree2"); !slices.Equal(got, []string{"hollow/", "sub/", "x.txt"}) {
		t.Fatalf("moved tree: %v", got)
	}
	if got := read("moved/tree2/sub/y.txt"); got != "y" {
		t.Fatalf("moved nested %q", got)
	}
	_, err = b.Stat(ctx, "tree")
	expectErr(err, ErrNotExist, "tree after move")

	expectErr(b.Move(ctx, "moved", "moved/inside"), ErrInvalidPath, "move into self")
	put("conflict.txt", "c")
	expectErr(b.Move(ctx, "n/deep/uno.txt", "conflict.txt"), ErrExist, "move onto existing")
	expectErr(b.Move(ctx, "nope", "x"), ErrNotExist, "move missing")

	// Recursive delete.
	if err := b.Delete(ctx, "moved", true); err != nil {
		t.Fatalf("recursive delete: %v", err)
	}
	_, err = b.Stat(ctx, "moved")
	expectErr(err, ErrNotExist, "after recursive delete")
	expectErr(b.Delete(ctx, "", true), ErrInvalidPath, "delete root")

	// Prefixed view is isolated and reports relative paths.
	p := Prefixed(b, "users/alice")
	if _, err := p.Put(ctx, "doc.txt", strings.NewReader("a"), 1, ""); err != nil {
		t.Fatal(err)
	}
	es, err := p.List(ctx, "")
	if err != nil || len(es) != 1 || es[0].Path != "doc.txt" {
		t.Fatalf("prefixed list: %+v %v", es, err)
	}
	if e, err := b.Stat(ctx, "users/alice/doc.txt"); err != nil || e.Size != 1 {
		t.Fatalf("prefixed write location: %v", err)
	}
}

func TestFilesystemConformance(t *testing.T) {
	fs, err := NewFilesystem(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	conformance(t, fs)
}

func TestFilesystemSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644)
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "abs"))
	os.Symlink("../"+filepath.Base(outside)+"/secret", filepath.Join(dir, "rel"))
	fs, err := NewFilesystem(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	for _, name := range []string{"abs", "rel"} {
		if _, _, err := fs.Open(context.Background(), name); err == nil {
			t.Fatalf("symlink %s escaped root", name)
		}
	}
	es, _ := fs.List(context.Background(), "")
	if len(es) != 0 {
		t.Fatalf("escaping symlinks listed: %+v", es)
	}
}

// TestS3Conformance runs against a real S3 compatible server. Set
// GS_TEST_S3_ENDPOINT, GS_TEST_S3_BUCKET, GS_TEST_S3_ACCESS_KEY and
// GS_TEST_S3_SECRET_KEY to enable it.
func TestS3Conformance(t *testing.T) {
	endpoint := os.Getenv("GS_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("GS_TEST_S3_ENDPOINT not set")
	}
	s3, err := NewS3(context.Background(), S3Options{
		Endpoint:  endpoint,
		Bucket:    os.Getenv("GS_TEST_S3_BUCKET"),
		AccessKey: os.Getenv("GS_TEST_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("GS_TEST_S3_SECRET_KEY"),
		Region:    os.Getenv("GS_TEST_S3_REGION"),
		PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var rnd [6]byte
	rand.Read(rnd[:])
	prefix := "conformance-" + hex.EncodeToString(rnd[:])
	b := Prefixed(s3, prefix)
	t.Cleanup(func() { s3.Delete(context.Background(), prefix, true) })
	conformance(t, b)
}

func TestClean(t *testing.T) {
	ok := map[string]string{"": "", "/": "", "a": "a", "/a/b/": "a/b", "a//b": "a/b", "./a/./b": "a/b"}
	for in, want := range ok {
		if got, err := Clean(in); err != nil || got != want {
			t.Errorf("Clean(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"..", "a/../b", "../etc", "a/..", "a\\b", "a\x00b"} {
		if _, err := Clean(bad); err == nil {
			t.Errorf("Clean(%q) accepted", bad)
		}
	}
}
