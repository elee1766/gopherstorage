// Package server exposes storage mounts over HTTP.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/elee1766/gopherstorage/internal/auth"
	"github.com/elee1766/gopherstorage/internal/config"
	"github.com/elee1766/gopherstorage/internal/storage"
)

//go:embed web
var webFS embed.FS

type Authenticator interface {
	Authenticate(r *http.Request) *auth.User
	Login(w http.ResponseWriter, r *http.Request)
	Callback(w http.ResponseWriter, r *http.Request)
	Logout(w http.ResponseWriter, r *http.Request)
}

type Server struct {
	auth      Authenticator
	mounts    map[string]*mount
	order     []string
	maxUpload int64
}

func New(cfg *config.Config, a Authenticator, backends map[string]storage.Backend) (*Server, error) {
	s := &Server{auth: a, mounts: map[string]*mount{}, maxUpload: cfg.MaxUploadBytes}
	for _, m := range cfg.Mounts {
		b, ok := backends[m.Backend]
		if !ok {
			return nil, fmt.Errorf("mount %q: backend %q not initialized", m.Name, m.Backend)
		}
		s.mounts[m.Name] = &mount{cfg: m, backend: b}
		s.order = append(s.order, m.Name)
	}
	return s, nil
}

// OpenBackends initializes every backend in the config.
func OpenBackends(ctx context.Context, cfg *config.Config) (map[string]storage.Backend, error) {
	out := map[string]storage.Backend{}
	for name, b := range cfg.Backends {
		var (
			be  storage.Backend
			err error
		)
		switch b.Type {
		case "filesystem":
			be, err = storage.NewFilesystem(b.Path)
		case "s3":
			var s3 *storage.S3
			s3, err = storage.NewS3(ctx, storage.S3Options{
				Endpoint: b.Endpoint, Region: b.Region, Bucket: b.Bucket,
				AccessKey: b.AccessKey, SecretKey: b.SecretKey, SessionToken: b.SessionToken,
				Insecure: b.Insecure, PathStyle: b.PathStyle,
			})
			if err == nil {
				prefix, perr := storage.Clean(b.Prefix)
				if perr != nil {
					return nil, fmt.Errorf("backend %q: invalid prefix", name)
				}
				be = storage.Prefixed(s3, prefix)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("backend %q: %w", name, err)
		}
		out[name] = be
	}
	return out, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /auth/login", s.auth.Login)
	mux.HandleFunc("GET /auth/callback", s.auth.Callback)
	mux.HandleFunc("GET /auth/logout", s.auth.Logout)
	mux.HandleFunc("POST /auth/logout", s.auth.Logout)

	mux.HandleFunc("GET /api/me", s.authed(s.handleMe))
	for _, pat := range []string{"/api/files/{mount}", "/api/files/{mount}/{path...}"} {
		mux.HandleFunc("GET "+pat, s.authed(s.handleGet))
		mux.HandleFunc("PUT "+pat, s.authed(s.handlePut))
		mux.HandleFunc("POST "+pat, s.authed(s.handlePost))
		mux.HandleFunc("DELETE "+pat, s.authed(s.handleDelete))
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { jsonError(w, http.StatusNotFound, "not found") })

	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(mustSub(webFS, "web"))))

	csrf := http.NewCrossOriginProtection()
	return logRequests(securityHeaders(csrf.Handler(mux)))
}

type ctxKey struct{}

func userFrom(r *http.Request) *auth.User { return r.Context().Value(ctxKey{}).(*auth.User) }

func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.auth.Authenticate(r)
		if u == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="gopherstorage"`)
			jsonError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	}
}

type mountInfo struct {
	Name     string `json:"name"`
	Writable bool   `json:"writable"`
	PerUser  bool   `json:"per_user"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	mounts := []mountInfo{}
	for _, name := range s.order {
		m := s.mounts[name]
		if m.canRead(u) {
			mounts = append(mounts, mountInfo{Name: name, Writable: m.canWrite(u), PerUser: m.cfg.PerUser()})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "mounts": mounts})
}

// target resolves the mount and path for a request and checks access.
func (s *Server) target(w http.ResponseWriter, r *http.Request, write bool) (storage.Backend, string, bool) {
	u := userFrom(r)
	m, ok := s.mounts[r.PathValue("mount")]
	if !ok || !m.canRead(u) {
		jsonError(w, http.StatusNotFound, "mount not found")
		return nil, "", false
	}
	if write && !m.canWrite(u) {
		jsonError(w, http.StatusForbidden, "mount is read only for you")
		return nil, "", false
	}
	p, err := storage.Clean(r.PathValue("path"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid path")
		return nil, "", false
	}
	b, err := m.resolve(u)
	if err != nil {
		jsonError(w, http.StatusForbidden, err.Error())
		return nil, "", false
	}
	if m.cfg.PerUser() {
		// Lazily create the user's home directory.
		if _, err := b.Stat(r.Context(), ""); errors.Is(err, storage.ErrNotExist) {
			if err := b.Mkdir(r.Context(), ""); err != nil {
				s.storageError(w, r, err)
				return nil, "", false
			}
		}
	}
	return b, p, true
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	b, p, ok := s.target(w, r, false)
	if !ok {
		return
	}
	ctx := r.Context()
	e, err := b.Stat(ctx, p)
	if err != nil {
		s.storageError(w, r, err)
		return
	}
	if e.IsDir {
		entries, err := b.List(ctx, p)
		if err != nil {
			s.storageError(w, r, err)
			return
		}
		if entries == nil {
			entries = []storage.Entry{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"entry": e, "entries": entries})
		return
	}
	if r.URL.Query().Has("stat") {
		writeJSON(w, http.StatusOK, map[string]any{"entry": e})
		return
	}
	f, e, err := b.Open(ctx, p)
	if err != nil {
		s.storageError(w, r, err)
		return
	}
	defer f.Close()
	h := w.Header()
	ct := e.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	if e.ETag != "" {
		h.Set("ETag", `"`+strings.Trim(e.ETag, `"`)+`"`)
	}
	// Uploaded content is untrusted. Never run it as active content on this origin.
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'")
	disp := "inline"
	if r.URL.Query().Has("download") {
		disp = "attachment"
	}
	h.Set("Content-Disposition", mime.FormatMediaType(disp, map[string]string{"filename": e.Name}))
	http.ServeContent(w, r, e.Name, e.ModTime, f)
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	b, p, ok := s.target(w, r, true)
	if !ok {
		return
	}
	if p == "" {
		jsonError(w, http.StatusBadRequest, "path is required")
		return
	}
	ctx := r.Context()
	if r.URL.Query().Get("overwrite") == "false" {
		if _, err := b.Stat(ctx, p); err == nil {
			jsonError(w, http.StatusConflict, "already exists")
			return
		}
	}
	size := r.ContentLength
	body := io.Reader(r.Body)
	if s.maxUpload > 0 {
		if size > s.maxUpload {
			jsonError(w, http.StatusRequestEntityTooLarge, "upload too large")
			return
		}
		body = http.MaxBytesReader(w, r.Body, s.maxUpload)
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" || strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		ct = mime.TypeByExtension(path.Ext(p))
	}
	e, err := b.Put(ctx, p, body, size, ct)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			jsonError(w, http.StatusRequestEntityTooLarge, "upload too large")
			return
		}
		s.storageError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"entry": e})
}

type moveRequest struct {
	To string `json:"to"`
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	op := r.URL.Query().Get("op")
	b, p, ok := s.target(w, r, true)
	if !ok {
		return
	}
	ctx := r.Context()
	switch op {
	case "mkdir":
		if err := b.Mkdir(ctx, p); err != nil {
			s.storageError(w, r, err)
			return
		}
		e, err := b.Stat(ctx, p)
		if err != nil {
			s.storageError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"entry": e})
	case "move":
		var req moveRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			jsonError(w, http.StatusBadRequest, "body must be JSON: {\"to\": \"path\"}")
			return
		}
		dst, err := storage.Clean(req.To)
		if err != nil || dst == "" || p == "" {
			jsonError(w, http.StatusBadRequest, "invalid path")
			return
		}
		if err := b.Move(ctx, p, dst); err != nil {
			s.storageError(w, r, err)
			return
		}
		e, err := b.Stat(ctx, dst)
		if err != nil {
			s.storageError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entry": e})
	default:
		jsonError(w, http.StatusBadRequest, "unknown op, want mkdir or move")
	}
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	b, p, ok := s.target(w, r, true)
	if !ok {
		return
	}
	if p == "" {
		jsonError(w, http.StatusBadRequest, "cannot delete mount root")
		return
	}
	recursive, _ := strconv.ParseBool(r.URL.Query().Get("recursive"))
	if err := b.Delete(r.Context(), p, recursive); err != nil {
		s.storageError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) storageError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, storage.ErrNotExist):
		jsonError(w, http.StatusNotFound, "not found")
	case errors.Is(err, storage.ErrExist):
		jsonError(w, http.StatusConflict, "already exists")
	case errors.Is(err, storage.ErrNotEmpty):
		jsonError(w, http.StatusConflict, "directory not empty, use recursive=true")
	case errors.Is(err, storage.ErrIsDir):
		jsonError(w, http.StatusConflict, "is a directory")
	case errors.Is(err, storage.ErrNotDir):
		jsonError(w, http.StatusConflict, "a parent path is a file")
	case errors.Is(err, storage.ErrInvalidPath):
		jsonError(w, http.StatusBadRequest, "invalid path")
	case errors.Is(err, context.Canceled):
		// client went away
	default:
		slog.Error("storage error", "method", r.Method, "path", r.URL.Path, "err", err)
		jsonError(w, http.StatusInternalServerError, "storage error")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, _ := webFS.ReadFile("web/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
	w.Write(data)
}

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		h.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		h.ServeHTTP(sw, r)
		if r.URL.Path == "/healthz" {
			return
		}
		slog.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "bytes", sw.bytes, "dur", time.Since(start).Round(time.Millisecond))
	})
}
