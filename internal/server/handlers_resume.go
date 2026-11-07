package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

const (
	resumeCookieName = "specht_resume"
	// resumeCookiePath keeps the cookie off every request but the one that reads it.
	resumeCookiePath = "/api/v1/auth/resume"
	// resumeRequestHeader must be present on a resume. A cross-site page cannot send
	// it without a preflight, which the server does not grant.
	resumeRequestHeader = "X-Specht-Resume"
)

// setResumeCookie gives this browser a way to continue a sign-in in a new tab. It
// is a session cookie, so closing the browser ends it, as closing a tab ended a
// session before. A failure here costs convenience, not the sign-in, so it is
// logged and the response goes on, but it clears any cookie this browser still
// holds: it may belong to someone who signed in here before.
func (h *Handler) setResumeCookie(w http.ResponseWriter, r *http.Request, refreshToken string) {
	token, err := h.usecase.IssueResumeToken(r.Context(), refreshToken)
	if err != nil {
		slog.Warn("issue resume token", "error", err)
		clearResumeCookie(w, r)
		return
	}
	// Secure comes from the proxy-aware transport verdict.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     resumeCookieName,
		Value:    token,
		Path:     resumeCookiePath,
		HttpOnly: true,
		Secure:   auth.SecureTransport(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func clearResumeCookie(w http.ResponseWriter, r *http.Request) {
	// Secure comes from the proxy-aware transport verdict.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     resumeCookieName,
		Path:     resumeCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   auth.SecureTransport(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// ResumeSession starts a session for a tab opened without one. It answers 204
// when there is nothing to resume, which is the normal state of a signed-out
// browser and not an error.
func (h *Handler) ResumeSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get(resumeRequestHeader) == "" {
		respondError(w, http.StatusForbidden, "resume_refused", "a resume needs the resume header")
		return
	}
	cookie, err := r.Cookie(resumeCookieName)
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	result, err := h.usecase.ResumeSession(r.Context(), cookie.Value)
	if err != nil {
		if !errors.Is(err, usecase.ErrNoResume) {
			slog.Error("resume session", "error", err)
		}
		clearResumeCookie(w, r)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// Each resume starts a new period, so an active browser keeps its sign-in and an
	// idle one does not.
	h.setResumeCookie(w, r, result.RefreshToken)
	respondJSON(w, http.StatusOK, result)
	h.audit.HTTP(r, audit.EventResume, audit.OutcomeSuccess, "", result.UserID, nil)
}
