//go:build integration

package repo

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/server"
	"github.com/minh-tg/specht/internal/usecase"
)

func TestFindingHandlersMaskForeignIDsButKeepMemberRoleDenials(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	user, err := s.stores.Users.Create(s.ctx, "outsider@example.test", nil, nil)
	require.NoError(t, err)
	h := server.NewHandler(usecase.New(usecase.Deps{Stores: s.stores}))
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: user.ID, Role: auth.RoleMember})))
		})
	})
	r.Get("/api/v1/findings/{id}", h.GetFinding)
	r.Post("/api/v1/findings/{findingID}/signoff", h.UpsertSignoff)
	r.Post("/api/v1/findings/bulk-analysis", h.BulkTriage)
	for _, member := range []bool{false, true} {
		if member {
			_, err = s.stores.Projects.UpsertMember(s.ctx, s.projectID, user.ID, "member")
			require.NoError(t, err)
		}
		for _, id := range []string{"11111111-1111-1111-1111-111111111111", s.findingID} {
			for _, op := range []string{"read", "signoff", "bulk"} {
				method, path, body := "GET", "/api/v1/findings/"+id, ""
				if op == "signoff" {
					method, path, body = "POST", path+"/signoff", `{"status":"pending"}`
				}
				if op == "bulk" {
					method, path, body = "POST", "/api/v1/findings/bulk-analysis", `{"finding_ids":["`+id+`"],"analysis_state":"in_triage"}`
				}
				w := httptest.NewRecorder()
				req := httptest.NewRequest(method, path, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				r.ServeHTTP(w, req)
				want := http.StatusNotFound
				if member && id == s.findingID {
					want = http.StatusForbidden
					if op == "read" {
						want = http.StatusOK
					}
				}
				require.Equal(t, want, w.Code, "member=%t operation=%s id=%s body=%s", member, op, id, w.Body.String())
			}
		}
	}
}
