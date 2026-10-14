package server

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/minh-tg/specht/internal/audit"
)

type auditTargetKey struct{}

// setAuditTarget names the target of the audited route in progress when only the handler knows
// it, for example the person a request body identified by email. It does nothing on a route that
// is not audited.
func setAuditTarget(r *http.Request, target string) {
	if slot, ok := r.Context().Value(auditTargetKey{}).(*string); ok {
		*slot = target
	}
}

// audited records one audit entry for the route when the handler returns: who did it, to which
// project and target, and how it ended. The project is the route's {slug}; the target is the first
// of the named path parameters that has a value. The outcome follows the status the handler wrote,
// so it needs no cooperation from the handler. Mount it after the group's authentication middleware
// (so the entry carries the principal) and before the route's own role guard, so a refused attempt
// is recorded too.
func (h *Handler) audited(event string, targetParams ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			var named string
			r = r.WithContext(context.WithValue(r.Context(), auditTargetKey{}, &named))
			next.ServeHTTP(ww, r)

			status := ww.Status()
			if status == 0 {
				status = http.StatusOK
			}
			outcome := audit.OutcomeSuccess
			switch {
			case status >= http.StatusInternalServerError:
				outcome = audit.OutcomeError
			case status >= http.StatusBadRequest:
				outcome = audit.OutcomeFailure
			}
			target := named
			for _, name := range targetParams {
				if target != "" {
					break
				}
				if v := chi.URLParam(r, name); v != "" {
					target = v
					break
				}
			}
			h.audit.HTTP(r, event, outcome, chi.URLParam(r, "slug"), target, nil)
		})
	}
}
