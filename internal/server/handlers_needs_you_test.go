package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/minh-tg/specht/internal/usecase"
)

func TestNeedsYou_Success(t *testing.T) {
	h := &Handler{usecase: &mockUsecases{
		getNeedsYouFn: func(context.Context) (*usecase.NeedsYouResponse, error) {
			return &usecase.NeedsYouResponse{
				Count: 1, AssignedFindings: 1,
				Items: []usecase.NeedsYouItem{{
					Kind: usecase.NeedsYouFindingAssigned, ProjectSlug: "my-app", ProjectName: "My app",
					Title: "lodash", Link: "/my-app/findings/f1",
				}},
			}, nil
		},
	}}
	w := httptest.NewRecorder()
	h.NeedsYou(w, httptest.NewRequest(http.MethodGet, "/api/v1/me/needs-you", nil))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "what waits on a person is never cached")
	var resp struct {
		Count int `json:"count"`
		Items []struct {
			Kind string `json:"kind"`
			Link string `json:"link"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Count)
	require.Len(t, resp.Items, 1)
	assert.Equal(t, "finding_assigned", resp.Items[0].Kind)
	assert.Equal(t, "/my-app/findings/f1", resp.Items[0].Link)
}

func TestNeedsYou_Errors(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code int
		want string
	}{
		"an API key": {err: usecase.ErrProjectAccessDenied, code: http.StatusForbidden, want: "project_access_denied"},
		"store down": {err: fmt.Errorf("db down"), code: http.StatusInternalServerError, want: "internal_error"},
	} {
		t.Run(name, func(t *testing.T) {
			h := &Handler{usecase: &mockUsecases{
				getNeedsYouFn: func(context.Context) (*usecase.NeedsYouResponse, error) { return nil, tc.err },
			}}
			w := httptest.NewRecorder()
			h.NeedsYou(w, httptest.NewRequest(http.MethodGet, "/api/v1/me/needs-you", nil))
			assert.Equal(t, tc.code, w.Code)
			assert.Contains(t, w.Body.String(), tc.want)
			assert.NotContains(t, w.Body.String(), "db down")
		})
	}
}

// The schemas in openapi.yaml name the fields the response carries, and each property holds only
// schema keywords. An unquoted description in a flow mapping ends at its first comma, and the
// rest of the sentence becomes a stray key that the generated client types drop without a word.
func TestNeedsYou_OpenAPISchemasMatchTheResponse(t *testing.T) {
	raw, err := os.ReadFile("../../openapi.yaml")
	require.NoError(t, err)
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &spec))

	keywords := []string{"type", "format", "description", "enum", "example", "items", "$ref"}
	for name, goType := range map[string]reflect.Type{
		"NeedsYouItem":     reflect.TypeFor[usecase.NeedsYouItem](),
		"NeedsYouResponse": reflect.TypeFor[usecase.NeedsYouResponse](),
	} {
		t.Run(name, func(t *testing.T) {
			schema, ok := spec.Components.Schemas[name]
			require.True(t, ok, "openapi.yaml has no schema %s", name)
			var documented, sent []string
			for prop, body := range schema.Properties {
				documented = append(documented, prop)
				for key := range body {
					assert.Contains(t, keywords, key, "%s.%s has a stray key", name, prop)
				}
			}
			for field := range goType.Fields() {
				sent = append(sent, strings.Split(field.Tag.Get("json"), ",")[0])
			}
			slices.Sort(documented)
			slices.Sort(sent)
			assert.Equal(t, sent, documented)
		})
	}
}
