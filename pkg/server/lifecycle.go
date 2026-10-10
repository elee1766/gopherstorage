package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/elee1766/gopherstorage/pkg/meta"
)

func registerLifecycleAPI(mux *http.ServeMux, s *Server) {
	mux.HandleFunc("PUT /api/v1/admin/users/{id}/access", s.apiHandler(true, s.setUserAccess))
	mux.HandleFunc("DELETE /api/v1/account/credentials", s.apiHandler(false, s.revokeOwnCredentials))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}/credentials", s.apiHandler(true, s.revokeUserCredentials))
}

func (s *Server) setUserAccess(w http.ResponseWriter, r *http.Request, p *principal) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var body struct {
		Disabled *bool `json:"disabled"`
	}
	if err := dec.Decode(&body); err != nil || body.Disabled == nil {
		jsonError(w, http.StatusBadRequest, "disabled must be a boolean")
		return
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if id == p.user.ID && *body.Disabled {
		jsonError(w, http.StatusBadRequest, "cannot disable the account used for this request")
		return
	}
	if err := s.store.SetUserDisabled(r.Context(), id, *body.Disabled); err != nil {
		if errors.Is(err, meta.ErrNotFound) {
			jsonError(w, http.StatusNotFound, "no such user")
			return
		}
		jsonError(w, http.StatusInternalServerError, "user access update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "disabled": *body.Disabled})
}

func (s *Server) revokeOwnCredentials(w http.ResponseWriter, r *http.Request, p *principal) {
	if err := s.store.RevokeUserCredentials(r.Context(), p.user.ID); err != nil {
		jsonError(w, http.StatusInternalServerError, "credential revocation failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) revokeUserCredentials(w http.ResponseWriter, r *http.Request, _ *principal) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	if err := s.store.RevokeUserCredentials(r.Context(), id); err != nil {
		if errors.Is(err, meta.ErrNotFound) {
			jsonError(w, http.StatusNotFound, "no such user")
			return
		}
		jsonError(w, http.StatusInternalServerError, "credential revocation failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
