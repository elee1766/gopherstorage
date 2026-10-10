package server

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"anime.bike/remotestorage/pkg/rs"

	"github.com/elee1766/gopherstorage/internal/auth"
	"github.com/elee1766/gopherstorage/internal/meta"
)

// ViewPrefix serves shared documents for display in browsers:
// /view/<user>/<path> shows /public/<path> of that user's storage.
const ViewPrefix = "/view/"

// viewKind decides how a content type is presented.
type viewKind int

const (
	viewDownload viewKind = iota // attachment
	viewInline                   // shown by the browser, passive content
	viewSandbox                  // shown, but scripts and same-origin access disabled
)

// inlineTypes are passive media types browsers display safely.
var inlineTypes = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true, "image/avif": true,
	"image/bmp": true, "image/x-icon": true, "image/vnd.microsoft.icon": true, "image/apng": true,
	"audio/mpeg": true, "audio/mp4": true, "audio/aac": true, "audio/ogg": true, "audio/opus": true,
	"audio/wav": true, "audio/x-wav": true, "audio/webm": true, "audio/flac": true, "audio/x-flac": true,
	"video/mp4": true, "video/webm": true, "video/ogg": true, "video/quicktime": true,
	"application/pdf": true, "text/plain": true, "text/markdown": true, "text/csv": true,
	"application/json": true,
}

// sandboxTypes can carry scripts; they are shown only under a CSP sandbox.
var sandboxTypes = map[string]bool{"text/html": true, "image/svg+xml": true, "application/xhtml+xml": true}

// viewType returns the media type to send and how to present it. Stored
// types are what apps sent; generic or missing types fall back to the
// file extension.
func viewType(stored, name string) (string, viewKind) {
	mt, params, err := mime.ParseMediaType(stored)
	if err != nil || mt == "" || mt == "application/octet-stream" || mt == "binary/octet-stream" {
		if byExt := mime.TypeByExtension(path.Ext(name)); byExt != "" {
			mt, params, _ = mime.ParseMediaType(byExt)
		} else {
			return "application/octet-stream", viewDownload
		}
	}
	full := mime.FormatMediaType(mt, params)
	switch {
	case inlineTypes[mt]:
		if strings.HasPrefix(mt, "text/") && params["charset"] == "" {
			params = map[string]string{"charset": "utf-8"}
			full = mime.FormatMediaType(mt, params)
		}
		return full, viewInline
	case sandboxTypes[mt]:
		return full, viewSandbox
	}
	return full, viewDownload
}

func (s *Server) handleView(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, ETag, Last-Modified, Content-Disposition")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if r.Method == http.MethodOptions {
		h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Range, If-None-Match, If-Modified-Since")
		h.Set("Access-Control-Max-Age", "86400")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD, OPTIONS")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.viewHostOK(r) {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.EscapedPath(), ViewPrefix)
	user, escaped, ok := strings.Cut(rest, "/")
	if !ok || !auth.ValidUsername(user) || escaped == "" || strings.HasSuffix(escaped, "/") {
		http.NotFound(w, r)
		return
	}
	docPath, err := unescapeDocPath("/public/" + escaped)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	u, err := s.store.UserByName(ctx, user)
	if errors.Is(err, meta.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if u.Disabled {
		http.NotFound(w, r)
		return
	}
	doc, _, err := s.storage.ForUser(u).Get(ctx, docPath)
	if errors.Is(err, rs.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil || doc == nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer doc.Body.Close()

	name := rs.BaseName(docPath)
	ct, kind := viewType(doc.Metadata.ContentType, name)
	disp := "inline"
	if kind == viewDownload || r.URL.Query().Has("download") || s.sameOriginView(r) && (kind == viewSandbox || ct == "application/pdf") && !s.cfg.View.AllowSameOrigin {
		disp = "attachment"
	}
	h.Set("Content-Type", ct)
	h.Set("Content-Disposition", mime.FormatMediaType(disp, map[string]string{"filename": name}))
	switch {
	case kind == viewSandbox && disp == "inline":
		// Shown as an isolated document: no scripts, no same-origin access,
		// and it may only load passive resources.
		h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src * data: blob:; media-src * data: blob:; style-src 'unsafe-inline' *; font-src *")
	case kind == viewInline && disp == "inline":
		// Passive media. No sandbox directive, since it breaks the built-in
		// PDF viewer; nosniff plus the type allowlist keep it passive.
		h.Set("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; object-src 'self'; frame-ancestors *")
	default:
		h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	}
	h.Set("ETag", `"`+doc.Metadata.ETag+`"`)
	h.Set("Cache-Control", s.viewCacheControl())

	body, ok := doc.Body.(io.ReadSeeker)
	if !ok {
		h.Set("Content-Length", strconv.FormatInt(doc.Metadata.Size, 10))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			io.Copy(w, doc.Body)
		}
		return
	}
	// ServeContent handles Range, If-Range, If-None-Match, If-Modified-Since and HEAD.
	http.ServeContent(w, r, "", doc.Metadata.LastModified.Truncate(time.Second), body)
}

func (s *Server) viewCacheControl() string {
	if s.cfg.View.CacheMaxAge > 0 {
		return "public, max-age=" + strconv.Itoa(int(s.cfg.View.CacheMaxAge.Seconds()))
	}
	return "public, no-cache"
}

// sameOriginView reports whether /view/ is served on the account hostname.
// Comparing hosts conservatively also covers TLS-terminating reverse proxies.
func (s *Server) sameOriginView(r *http.Request) bool {
	public, err := url.Parse(s.cfg.PublicURL)
	return err == nil && public.Host != "" && strings.EqualFold(r.Host, public.Host)
}

// viewHostOK enforces the dedicated view host, if one is configured, so
// shared content is never served from the account origin unless explicitly allowed.
func (s *Server) viewHostOK(r *http.Request) bool {
	vh := s.cfg.ViewHost()
	return vh == "" || strings.EqualFold(r.Host, vh)
}

// ViewURL returns the share link of a public document path ("/public/...").
func (s *Server) ViewURL(user, publicPath string) string {
	base := s.cfg.PublicURL
	if s.cfg.View.URL != "" {
		base = s.cfg.View.URL
	}
	segs := strings.Split(strings.TrimPrefix(publicPath, "/public/"), "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return base + ViewPrefix + user + "/" + strings.Join(segs, "/")
}

func unescapeDocPath(escaped string) (string, error) {
	segs := strings.Split(escaped, "/")
	for i, seg := range segs {
		u, err := url.PathUnescape(seg)
		if err != nil || strings.Contains(u, "/") {
			return "", rs.ErrInvalidPath
		}
		segs[i] = u
	}
	p := strings.Join(segs, "/")
	if err := rs.ValidatePath(p); err != nil || rs.IsFolderPath(p) {
		return "", rs.ErrInvalidPath
	}
	return p, nil
}
